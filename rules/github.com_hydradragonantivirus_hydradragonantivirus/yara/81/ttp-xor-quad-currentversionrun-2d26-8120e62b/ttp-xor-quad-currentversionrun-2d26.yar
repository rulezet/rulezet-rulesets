rule TTP_XOR_QUAD_CurrentVersionRun_2d26 {
  strings:
    $key_2d26 = { 7e 49 [2] 5a 47 [2] 71 6b [2] 5f 49 [2] 4b 52 [2] 44 48 [2] 5a 55 [2] 58 54 [2] 43 52 [2] 5f 55 [2] 43 7a }

  condition:
    any of them
}