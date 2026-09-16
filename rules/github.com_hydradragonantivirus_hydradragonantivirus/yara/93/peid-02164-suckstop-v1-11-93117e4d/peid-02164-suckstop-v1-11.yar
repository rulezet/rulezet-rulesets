rule PEiD_02164_SuckStop_v1_11_ {
  meta:
    description = "[SuckStop v1.11]"
    ep_only     = "true"

  strings:
    $a = { EB ?? ?? ?? BE ?? ?? B4 30 CD 21 EB ?? 9B }

  condition:
    $a
}