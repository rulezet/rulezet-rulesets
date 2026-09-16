rule PEiD_00398_CopyControl_v3_03_ {
  meta:
    description = "[CopyControl v3.03]"
    ep_only     = "true"

  strings:
    $a = { CC 90 90 EB 0B 01 50 51 52 53 54 61 33 61 2D 35 CA D1 07 52 D1 A1 3C }

  condition:
    $a
}