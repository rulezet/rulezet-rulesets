rule TTP_XOR_QUAD_CurrentVersionRun_ea51 {
  strings:
    $key_ea51 = { b9 3e [2] 9d 30 [2] b6 1c [2] 98 3e [2] 8c 25 [2] 83 3f [2] 9d 22 [2] 9f 23 [2] 84 25 [2] 98 22 [2] 84 0d }

  condition:
    any of them
}