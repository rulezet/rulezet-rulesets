import "elf"
rule apt_CN_31_sowat_code {
  meta:
    author      = "@imp0rtp3"
    description = "Apt31 router implant (SoWaT) unique code (relevant only for MIPS)"
    reference   = "https://imp0rtp3.wordpress.com/2021/11/25/sowat/"

  strings:
    $c1 = { 25 38 00 00 [8] 38 00 1? 9A 09 F8 20 03 2? 20 A0 02 10 40 92 8E }
    $c2 = { 06 00 30 12 25 20 00 02 04 00 70 12 00 00 00 00 09 F8 20 03 00 00 00 00 ?? 00 BC 8F 01 00 10 26 }
    $c3 = { 00 01 02 24 25 38 00 00 02 00 06 24 ?? 00 A2 A7 09 F8 20 03 ?? 00 A5 27 }
    $c4 = { 09 F8 20 03 25 20 ?0 02 0B 00 02 24 0? 00 22 12 ?? 00 BC 8F }
    $c5 = { ?5 26 ?? 00 BC 8F ?? ?? 99 8F 09 F8 20 03 10 00 04 24 ?? ?? ?5 26 ?? 00 BC 8F ?? ?? 99 8F 09 F8 20 03 0F 00 04 24 01 00 05 24 ?? 00 BC 8F ?? ?? 99 8F 09 F8 20 03 0D 00 04 24 ?? ?? ?5 26 ?? 00 BC 8F ?? ?? 99 8F 09 F8 20 03 0A 00 04 24 }
    $c6 = { 08 00 03 3C ?? ?? 99 8F 04 00 05 24 80 00 63 24 25 20 00 0? 09 F8 20 03 25 30 43 00 ?? 00 40 04 ?? 00 BC 8F ?? ?? 99 8F 01 00 05 24 09 F8 20 03 0D 00 04 24 }

  condition:
    uint32(0) == 0x464c457f and
    filesize < 2MB and
    (
      elf.machine == elf.EM_MIPS_RS3_LE or
      elf.machine == elf.EM_MIPS
    ) and 4 of ($c*)

}