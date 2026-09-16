rule TTP_XOR_QUAD_CurrentVersionRun_ea1a {
  strings:
    $key_ea1a = { b9 75 [2] 9d 7b [2] b6 57 [2] 98 75 [2] 8c 6e [2] 83 74 [2] 9d 69 [2] 9f 68 [2] 84 6e [2] 98 69 [2] 84 46 }

  condition:
    any of them
}