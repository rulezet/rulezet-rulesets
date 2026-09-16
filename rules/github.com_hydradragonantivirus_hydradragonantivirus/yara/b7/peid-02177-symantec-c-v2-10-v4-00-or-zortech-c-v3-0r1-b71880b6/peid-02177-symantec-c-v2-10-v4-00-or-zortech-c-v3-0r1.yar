rule PEiD_02177_Symantec_C_v2_10__v4_00_or_Zortech_C_v3_0r1_ {
  meta:
    description = "[Symantec C v2.10, v4.00 or Zortech C v3.0r1]"
    ep_only     = "true"

  strings:
    $a = { FA FC B8 ?? ?? 8E D8 }

  condition:
    $a
}