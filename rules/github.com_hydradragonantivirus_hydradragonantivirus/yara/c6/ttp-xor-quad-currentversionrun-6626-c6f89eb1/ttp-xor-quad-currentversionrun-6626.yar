rule TTP_XOR_QUAD_CurrentVersionRun_6626 {
  strings:
    $key_6626 = { 35 49 [2] 11 47 [2] 3a 6b [2] 14 49 [2] 00 52 [2] 0f 48 [2] 11 55 [2] 13 54 [2] 08 52 [2] 14 55 [2] 08 7a }

  condition:
    any of them
}