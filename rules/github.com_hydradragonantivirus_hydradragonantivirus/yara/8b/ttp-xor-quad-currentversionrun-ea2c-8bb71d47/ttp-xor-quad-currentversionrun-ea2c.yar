rule TTP_XOR_QUAD_CurrentVersionRun_ea2c {
  strings:
    $key_ea2c = { b9 43 [2] 9d 4d [2] b6 61 [2] 98 43 [2] 8c 58 [2] 83 42 [2] 9d 5f [2] 9f 5e [2] 84 58 [2] 98 5f [2] 84 70 }

  condition:
    any of them
}