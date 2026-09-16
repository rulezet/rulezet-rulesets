rule TTP_XOR_QUAD_CurrentVersionRun_ea5d {
  strings:
    $key_ea5d = { b9 32 [2] 9d 3c [2] b6 10 [2] 98 32 [2] 8c 29 [2] 83 33 [2] 9d 2e [2] 9f 2f [2] 84 29 [2] 98 2e [2] 84 01 }

  condition:
    any of them
}