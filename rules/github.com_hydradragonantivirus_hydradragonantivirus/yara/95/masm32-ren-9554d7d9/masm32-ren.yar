import "pe"
rule MASM32_ren: Packer PEiD {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 6A ?? 68 00 30 40 00 68 ?? 30 40 00 6A 00 E8 07 00 00 00 6A 00 E8 06 00 00 00 FF 25 08 20 }

  condition:
    $a0 at pe.entry_point
}