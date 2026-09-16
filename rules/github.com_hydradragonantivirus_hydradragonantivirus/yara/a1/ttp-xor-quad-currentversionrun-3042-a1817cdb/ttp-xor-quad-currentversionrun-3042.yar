rule TTP_XOR_QUAD_CurrentVersionRun_3042 {
  strings:
    $key_3042 = { 63 2d [2] 47 23 [2] 6c 0f [2] 42 2d [2] 56 36 [2] 59 2c [2] 47 31 [2] 45 30 [2] 5e 36 [2] 42 31 [2] 5e 1e }

  condition:
    any of them
}