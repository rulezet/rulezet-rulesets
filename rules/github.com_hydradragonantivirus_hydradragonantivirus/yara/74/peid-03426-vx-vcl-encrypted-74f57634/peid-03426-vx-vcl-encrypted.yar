rule PEiD_03426_Vx__VCL__encrypted__ {
  meta:
    description = "[Vx: VCL (encrypted)]"
    ep_only     = "true"

  strings:
    $a = { 01 B9 ?? ?? 81 35 ?? ?? 47 47 E2 F8 C3 }

  condition:
    $a
}