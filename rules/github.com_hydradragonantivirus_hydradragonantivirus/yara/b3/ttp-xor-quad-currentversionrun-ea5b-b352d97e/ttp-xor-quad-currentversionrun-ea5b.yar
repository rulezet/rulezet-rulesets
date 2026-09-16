rule TTP_XOR_QUAD_CurrentVersionRun_ea5b {
  strings:
    $key_ea5b = { b9 34 [2] 9d 3a [2] b6 16 [2] 98 34 [2] 8c 2f [2] 83 35 [2] 9d 28 [2] 9f 29 [2] 84 2f [2] 98 28 [2] 84 07 }

  condition:
    any of them
}