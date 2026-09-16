rule TTP_XOR_QUAD_CurrentVersionRun_6927 {
  strings:
    $key_6927 = { 3a 48 [2] 1e 46 [2] 35 6a [2] 1b 48 [2] 0f 53 [2] 00 49 [2] 1e 54 [2] 1c 55 [2] 07 53 [2] 1b 54 [2] 07 7b }

  condition:
    any of them
}