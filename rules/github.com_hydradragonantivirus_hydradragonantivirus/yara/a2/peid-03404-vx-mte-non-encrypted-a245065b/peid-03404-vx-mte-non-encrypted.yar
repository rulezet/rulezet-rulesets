rule PEiD_03404_Vx__MTE__non_encrypted__ {
  meta:
    description = "[Vx: MTE (non-encrypted)]"
    ep_only     = "true"

  strings:
    $a = { F7 D9 80 E1 FE 75 02 49 49 97 A3 ?? ?? 03 C1 24 FE 75 02 48 }

  condition:
    $a
}