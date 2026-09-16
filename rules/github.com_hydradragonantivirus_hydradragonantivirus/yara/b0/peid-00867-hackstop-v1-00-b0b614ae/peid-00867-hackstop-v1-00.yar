rule PEiD_00867_HACKSTOP_v1_00_ {
  meta:
    description = "[HACKSTOP v1.00]"
    ep_only     = "true"

  strings:
    $a = { FA BD ?? ?? FF E5 6A 49 48 0C ?? E4 ?? 3F 98 3F }

  condition:
    $a
}