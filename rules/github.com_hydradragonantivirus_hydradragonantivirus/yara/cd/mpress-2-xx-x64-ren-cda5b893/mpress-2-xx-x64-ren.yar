import "pe"
rule mpress_2_xx_x64_ren: Matcode {
  meta:
    author      = "Kevin Falcoz / _pusher_"
    date_create = "19/03/2013"
    last_edit   = "10/09/2016"
    description = "MPRESS v2.XX x64  - no .NET"

  strings:
    $a0 = { 57 56 53 51 52 41 50 48 8D 05 ?? ?? 00 00 48 8B 30 48 03 F0 48 2B C0 48 8B FE 66 AD C1 E0 0C 48 8B C8 50 AD 2B C8 48 03 F1 8B C8 57 44 8B C1 FF C9 8A 44 39 06 88 04 31 }

  condition:
    $a0 at pe.entry_point
}