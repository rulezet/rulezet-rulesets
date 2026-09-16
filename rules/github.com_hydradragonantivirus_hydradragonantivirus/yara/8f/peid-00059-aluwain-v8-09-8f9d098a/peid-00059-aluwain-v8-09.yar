rule PEiD_00059_Aluwain_v8_09_ {
  meta:
    description = "[Aluwain v8.09]"
    ep_only     = "true"

  strings:
    $a = { 8B EC 1E E8 ?? ?? 9D 5E }

  condition:
    $a
}