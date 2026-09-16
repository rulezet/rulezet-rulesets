rule PEiD_00007__pirit_v1_5_ {
  meta:
    description = "[$pirit v1.5]"
    ep_only     = "true"

  strings:
    $a = { ?? ?? ?? 5B 24 55 50 44 FB 32 2E 31 5D }

  condition:
    $a
}