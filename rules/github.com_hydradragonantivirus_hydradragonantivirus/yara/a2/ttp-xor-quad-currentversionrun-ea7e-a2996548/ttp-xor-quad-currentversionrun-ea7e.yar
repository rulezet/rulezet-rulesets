rule TTP_XOR_QUAD_CurrentVersionRun_ea7e {
  strings:
    $key_ea7e = { b9 11 [2] 9d 1f [2] b6 33 [2] 98 11 [2] 8c 0a [2] 83 10 [2] 9d 0d [2] 9f 0c [2] 84 0a [2] 98 0d [2] 84 22 }

  condition:
    any of them
}