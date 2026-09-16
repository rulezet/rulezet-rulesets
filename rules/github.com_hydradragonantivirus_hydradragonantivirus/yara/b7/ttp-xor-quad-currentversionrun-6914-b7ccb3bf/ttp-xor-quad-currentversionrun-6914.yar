rule TTP_XOR_QUAD_CurrentVersionRun_6914 {
  strings:
    $key_6914 = { 3a 7b [2] 1e 75 [2] 35 59 [2] 1b 7b [2] 0f 60 [2] 00 7a [2] 1e 67 [2] 1c 66 [2] 07 60 [2] 1b 67 [2] 07 48 }

  condition:
    any of them
}