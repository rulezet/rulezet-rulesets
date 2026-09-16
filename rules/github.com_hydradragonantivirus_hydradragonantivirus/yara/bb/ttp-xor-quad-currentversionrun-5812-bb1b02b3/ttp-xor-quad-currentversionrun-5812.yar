rule TTP_XOR_QUAD_CurrentVersionRun_5812 {
  strings:
    $key_5812 = { 0b 7d [2] 2f 73 [2] 04 5f [2] 2a 7d [2] 3e 66 [2] 31 7c [2] 2f 61 [2] 2d 60 [2] 36 66 [2] 2a 61 [2] 36 4e }

  condition:
    any of them
}