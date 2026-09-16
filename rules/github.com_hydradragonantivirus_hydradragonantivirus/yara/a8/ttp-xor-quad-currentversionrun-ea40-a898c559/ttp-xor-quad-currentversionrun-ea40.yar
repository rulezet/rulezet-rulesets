rule TTP_XOR_QUAD_CurrentVersionRun_ea40 {
  strings:
    $key_ea40 = { b9 2f [2] 9d 21 [2] b6 0d [2] 98 2f [2] 8c 34 [2] 83 2e [2] 9d 33 [2] 9f 32 [2] 84 34 [2] 98 33 [2] 84 1c }

  condition:
    any of them
}