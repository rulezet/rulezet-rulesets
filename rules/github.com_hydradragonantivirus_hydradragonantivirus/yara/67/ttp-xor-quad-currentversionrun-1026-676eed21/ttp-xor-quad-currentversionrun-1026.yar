rule TTP_XOR_QUAD_CurrentVersionRun_1026 {
  strings:
    $key_1026 = { 43 49 [2] 67 47 [2] 4c 6b [2] 62 49 [2] 76 52 [2] 79 48 [2] 67 55 [2] 65 54 [2] 7e 52 [2] 62 55 [2] 7e 7a }

  condition:
    any of them
}