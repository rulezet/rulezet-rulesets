rule TTP_XOR_QUAD_CurrentVersionRun_6826 {
  strings:
    $key_6826 = { 3b 49 [2] 1f 47 [2] 34 6b [2] 1a 49 [2] 0e 52 [2] 01 48 [2] 1f 55 [2] 1d 54 [2] 06 52 [2] 1a 55 [2] 06 7a }

  condition:
    any of them
}