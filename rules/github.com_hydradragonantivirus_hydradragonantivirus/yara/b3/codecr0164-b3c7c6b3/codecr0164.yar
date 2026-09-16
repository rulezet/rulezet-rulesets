import "pe"
rule codecr0164 {
  meta:
    author      = "PEiD"
    description = "CodeCrypt 0.164 -> defiler"
    group       = "110"
    function    = "0"

  strings:
    $a0 = { E9 2E 03 ?? ?? EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F EB 03 FF 1D 34 }

  condition:
    $a0 at pe.entry_point
}