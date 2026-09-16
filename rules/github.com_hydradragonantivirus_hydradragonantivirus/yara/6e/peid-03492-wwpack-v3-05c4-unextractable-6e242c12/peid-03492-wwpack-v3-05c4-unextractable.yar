rule PEiD_03492_WWPACK_v3_05c4__Unextractable__ {
  meta:
    description = "[WWPACK v3.05c4 (Unextractable)]"
    ep_only     = "true"

  strings:
    $a = { 03 05 00 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

  condition:
    $a
}