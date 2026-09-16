rule TTP_XOR_QUAD_CurrentVersionRun_3626 {
  strings:
    $key_3626 = { 65 49 [2] 41 47 [2] 6a 6b [2] 44 49 [2] 50 52 [2] 5f 48 [2] 41 55 [2] 43 54 [2] 58 52 [2] 44 55 [2] 58 7a }

  condition:
    any of them
}