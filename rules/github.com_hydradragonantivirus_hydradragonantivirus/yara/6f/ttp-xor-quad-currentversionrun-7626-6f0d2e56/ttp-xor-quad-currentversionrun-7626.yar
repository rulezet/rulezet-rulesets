rule TTP_XOR_QUAD_CurrentVersionRun_7626 {
  strings:
    $key_7626 = { 25 49 [2] 01 47 [2] 2a 6b [2] 04 49 [2] 10 52 [2] 1f 48 [2] 01 55 [2] 03 54 [2] 18 52 [2] 04 55 [2] 18 7a }

  condition:
    any of them
}