rule PEiD_03425_Vx__VCL__encrypted__ {
  meta:
    description = "[Vx: VCL (encrypted)]"
    ep_only     = "true"

  strings:
    $a = { 01 B9 ?? ?? 81 34 ?? ?? 46 46 E2 F8 C3 }

  condition:
    $a
}