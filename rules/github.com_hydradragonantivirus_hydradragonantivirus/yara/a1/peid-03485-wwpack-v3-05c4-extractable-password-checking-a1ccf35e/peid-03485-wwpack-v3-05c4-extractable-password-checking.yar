rule PEiD_03485_WWPACK_v3_05c4__Extractable___Password_checking__ {
  meta:
    description = "[WWPACK v3.05c4 (Extractable + Password checking)]"
    ep_only     = "true"

  strings:
    $a = { 03 05 80 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

  condition:
    $a
}