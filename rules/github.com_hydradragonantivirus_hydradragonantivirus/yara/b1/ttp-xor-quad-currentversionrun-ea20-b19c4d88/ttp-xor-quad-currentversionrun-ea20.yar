rule TTP_XOR_QUAD_CurrentVersionRun_ea20 {
  strings:
    $key_ea20 = { b9 4f [2] 9d 41 [2] b6 6d [2] 98 4f [2] 8c 54 [2] 83 4e [2] 9d 53 [2] 9f 52 [2] 84 54 [2] 98 53 [2] 84 7c }

  condition:
    any of them
}