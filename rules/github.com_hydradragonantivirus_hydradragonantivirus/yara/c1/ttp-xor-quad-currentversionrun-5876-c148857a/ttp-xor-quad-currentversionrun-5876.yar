rule TTP_XOR_QUAD_CurrentVersionRun_5876 {
  strings:
    $key_5876 = { 0b 19 [2] 2f 17 [2] 04 3b [2] 2a 19 [2] 3e 02 [2] 31 18 [2] 2f 05 [2] 2d 04 [2] 36 02 [2] 2a 05 [2] 36 2a }

  condition:
    any of them
}