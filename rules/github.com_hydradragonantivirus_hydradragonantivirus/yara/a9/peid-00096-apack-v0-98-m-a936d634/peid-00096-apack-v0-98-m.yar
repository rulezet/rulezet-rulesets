rule PEiD_00096_aPack_v0_98__m_ {
  meta:
    description = "[aPack v0.98 -m]"
    ep_only     = "false"

  strings:
    $a = { 1E 06 8C C8 8E D8 05 ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B2 ?? BD ?? ?? 33 C9 50 A4 BB ?? ?? 3B F3 76 }

  condition:
    $a
}