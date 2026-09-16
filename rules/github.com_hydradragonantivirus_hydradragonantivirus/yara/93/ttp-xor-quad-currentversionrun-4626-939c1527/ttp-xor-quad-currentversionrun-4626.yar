rule TTP_XOR_QUAD_CurrentVersionRun_4626 {
  strings:
    $key_4626 = { 15 49 [2] 31 47 [2] 1a 6b [2] 34 49 [2] 20 52 [2] 2f 48 [2] 31 55 [2] 33 54 [2] 28 52 [2] 34 55 [2] 28 7a }

  condition:
    any of them
}