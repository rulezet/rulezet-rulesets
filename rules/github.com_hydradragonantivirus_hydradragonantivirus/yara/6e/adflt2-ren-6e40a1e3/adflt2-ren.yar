import "pe"
rule AdFlt2_ren: Packer PEiD {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 68 00 01 9C 0F A0 0F A8 60 FD 6A 00 0F A1 BE ?? ?? AD }

  condition:
    $a0 at pe.entry_point
}