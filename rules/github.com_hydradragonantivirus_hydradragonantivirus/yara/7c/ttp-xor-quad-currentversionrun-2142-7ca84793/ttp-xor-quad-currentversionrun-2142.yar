rule TTP_XOR_QUAD_CurrentVersionRun_2142 {
  strings:
    $key_2142 = { 72 2d [2] 56 23 [2] 7d 0f [2] 53 2d [2] 47 36 [2] 48 2c [2] 56 31 [2] 54 30 [2] 4f 36 [2] 53 31 [2] 4f 1e }

  condition:
    any of them
}