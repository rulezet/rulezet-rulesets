import "pe"
rule _PECrc32_088__ZhouJinYu_ {
  meta:
    description = "PECrc32 0.88 -> ZhouJinYu"

  strings:
    $0 = { 60 E8 00 00 00 00 5D 81 ED B6 A4 45 00 8D BD B0 A4 45 00 81 EF 82 00 00 00 }

  condition:
    $0 at pe.entry_point
}