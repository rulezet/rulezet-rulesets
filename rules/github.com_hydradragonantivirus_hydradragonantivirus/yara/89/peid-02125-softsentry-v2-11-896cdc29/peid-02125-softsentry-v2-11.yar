rule PEiD_02125_SoftSentry_v2_11_ {
  meta:
    description = "[SoftSentry v2.11]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 EC ?? 53 56 57 E9 50 }

  condition:
    $a
}