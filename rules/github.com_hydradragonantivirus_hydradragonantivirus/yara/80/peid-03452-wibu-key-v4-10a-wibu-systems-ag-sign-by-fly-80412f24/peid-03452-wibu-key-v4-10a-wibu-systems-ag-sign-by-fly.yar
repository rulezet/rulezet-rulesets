rule PEiD_03452_WIBU_Key_V4_10A____WIBU_SYSTEMS_AG___Sign_by_fly_ {
  meta:
    description = "[WIBU-Key V4.10A -> WIBU-SYSTEMS AG ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { F7 05 ?? ?? ?? ?? FF 00 00 00 75 12 }

  condition:
    $a
}