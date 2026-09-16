rule PEiD_00021_A3E__TXT2COM__ {
  meta:
    description = "[A3E (TXT2COM)]"
    ep_only     = "true"

  strings:
    $a = { 1E 33 C0 50 BE ?? ?? 81 C6 ?? ?? B8 ?? ?? 8E C0 BF ?? ?? B9 ?? ?? F3 A5 CB }

  condition:
    $a
}