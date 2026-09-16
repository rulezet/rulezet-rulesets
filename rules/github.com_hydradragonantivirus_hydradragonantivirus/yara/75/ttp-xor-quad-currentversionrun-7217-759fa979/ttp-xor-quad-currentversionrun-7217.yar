rule TTP_XOR_QUAD_CurrentVersionRun_7217 {
  strings:
    $key_7217 = { 21 78 [2] 05 76 [2] 2e 5a [2] 00 78 [2] 14 63 [2] 1b 79 [2] 05 64 [2] 07 65 [2] 1c 63 [2] 00 64 [2] 1c 4b }

  condition:
    any of them
}