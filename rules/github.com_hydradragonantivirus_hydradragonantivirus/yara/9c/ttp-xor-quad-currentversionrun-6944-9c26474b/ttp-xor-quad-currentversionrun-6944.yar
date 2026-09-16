rule TTP_XOR_QUAD_CurrentVersionRun_6944 {
  strings:
    $key_6944 = { 3a 2b [2] 1e 25 [2] 35 09 [2] 1b 2b [2] 0f 30 [2] 00 2a [2] 1e 37 [2] 1c 36 [2] 07 30 [2] 1b 37 [2] 07 18 }

  condition:
    any of them
}