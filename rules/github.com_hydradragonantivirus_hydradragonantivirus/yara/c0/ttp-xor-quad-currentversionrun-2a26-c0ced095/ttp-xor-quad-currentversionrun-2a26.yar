rule TTP_XOR_QUAD_CurrentVersionRun_2a26 {
  strings:
    $key_2a26 = { 79 49 [2] 5d 47 [2] 76 6b [2] 58 49 [2] 4c 52 [2] 43 48 [2] 5d 55 [2] 5f 54 [2] 44 52 [2] 58 55 [2] 44 7a }

  condition:
    any of them
}