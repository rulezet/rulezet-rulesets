rule TTP_XOR_QUAD_CurrentVersionRun_ea00 {
  strings:
    $key_ea00 = { b9 6f [2] 9d 61 [2] b6 4d [2] 98 6f [2] 8c 74 [2] 83 6e [2] 9d 73 [2] 9f 72 [2] 84 74 [2] 98 73 [2] 84 5c }

  condition:
    any of them
}