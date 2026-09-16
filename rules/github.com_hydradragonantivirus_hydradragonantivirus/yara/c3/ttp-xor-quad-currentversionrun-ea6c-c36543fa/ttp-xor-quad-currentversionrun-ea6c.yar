rule TTP_XOR_QUAD_CurrentVersionRun_ea6c {
  strings:
    $key_ea6c = { b9 03 [2] 9d 0d [2] b6 21 [2] 98 03 [2] 8c 18 [2] 83 02 [2] 9d 1f [2] 9f 1e [2] 84 18 [2] 98 1f [2] 84 30 }

  condition:
    any of them
}