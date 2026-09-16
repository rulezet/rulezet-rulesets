rule TTP_XOR_QUAD_CurrentVersionRun_ea62 {
  strings:
    $key_ea62 = { b9 0d [2] 9d 03 [2] b6 2f [2] 98 0d [2] 8c 16 [2] 83 0c [2] 9d 11 [2] 9f 10 [2] 84 16 [2] 98 11 [2] 84 3e }

  condition:
    any of them
}