rule PEiD_00094_aPack_v0_62_ {
  meta:
    description = "[aPack v0.62]"
    ep_only     = "true"

  strings:
    $a = { 1E 06 8C C8 8E D8 ?? ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B6 }

  condition:
    $a
}