rule TTP_XOR_QUAD_CurrentVersionRun_ea2b {
  strings:
    $key_ea2b = { b9 44 [2] 9d 4a [2] b6 66 [2] 98 44 [2] 8c 5f [2] 83 45 [2] 9d 58 [2] 9f 59 [2] 84 5f [2] 98 58 [2] 84 77 }

  condition:
    any of them
}