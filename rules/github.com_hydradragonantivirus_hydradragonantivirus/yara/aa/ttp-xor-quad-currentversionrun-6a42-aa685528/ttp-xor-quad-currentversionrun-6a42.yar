rule TTP_XOR_QUAD_CurrentVersionRun_6a42 {
  strings:
    $key_6a42 = { 39 2d [2] 1d 23 [2] 36 0f [2] 18 2d [2] 0c 36 [2] 03 2c [2] 1d 31 [2] 1f 30 [2] 04 36 [2] 18 31 [2] 04 1e }

  condition:
    any of them
}