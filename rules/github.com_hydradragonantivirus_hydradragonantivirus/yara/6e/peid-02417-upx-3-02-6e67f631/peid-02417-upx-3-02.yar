rule PEiD_02417_UPX_3_02_ {
  meta:
    description = "[UPX 3.02]"
    ep_only     = "true"

  strings:
    $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C }

  condition:
    $a
}