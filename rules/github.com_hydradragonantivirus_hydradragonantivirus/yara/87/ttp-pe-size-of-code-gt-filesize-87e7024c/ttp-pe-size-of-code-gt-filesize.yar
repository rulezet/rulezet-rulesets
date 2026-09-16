import "pe"
rule ttp_pe_size_of_code_gt_filesize: ttp {
  meta:
    author      = "stvemillertime"
    description = "where size_of_code IMAGE_OPTIONAL_HEADER::SizeOfCode is larger than the actual file size. weird."
    hash        = "3dc11072110077584b00003536d0f3ba"

  condition:
    uint16be(0) == 0x4d5a
    and pe.size_of_code > filesize
}