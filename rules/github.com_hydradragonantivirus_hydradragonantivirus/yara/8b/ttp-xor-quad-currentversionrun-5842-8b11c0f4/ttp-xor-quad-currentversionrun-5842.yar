rule TTP_XOR_QUAD_CurrentVersionRun_5842 {
  strings:
    $key_5842 = { 0b 2d [2] 2f 23 [2] 04 0f [2] 2a 2d [2] 3e 36 [2] 31 2c [2] 2f 31 [2] 2d 30 [2] 36 36 [2] 2a 31 [2] 36 1e }

  condition:
    any of them
}