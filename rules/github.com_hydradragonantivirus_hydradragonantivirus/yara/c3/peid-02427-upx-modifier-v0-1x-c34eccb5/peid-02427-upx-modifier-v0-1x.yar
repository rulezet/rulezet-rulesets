rule PEiD_02427_UPX_Modifier_v0_1x_ {
  meta:
    description = "[UPX Modifier v0.1x]"
    ep_only     = "true"

  strings:
    $a = { 50 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }

  condition:
    $a
}