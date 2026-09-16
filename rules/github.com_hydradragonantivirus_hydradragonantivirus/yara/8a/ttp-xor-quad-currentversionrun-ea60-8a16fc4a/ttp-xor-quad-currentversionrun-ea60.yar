rule TTP_XOR_QUAD_CurrentVersionRun_ea60 {
  strings:
    $key_ea60 = { b9 0f [2] 9d 01 [2] b6 2d [2] 98 0f [2] 8c 14 [2] 83 0e [2] 9d 13 [2] 9f 12 [2] 84 14 [2] 98 13 [2] 84 3c }

  condition:
    any of them
}