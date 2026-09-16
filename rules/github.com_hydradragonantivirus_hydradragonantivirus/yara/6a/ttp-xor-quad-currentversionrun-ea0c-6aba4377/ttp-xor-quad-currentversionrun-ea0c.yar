rule TTP_XOR_QUAD_CurrentVersionRun_ea0c {
  strings:
    $key_ea0c = { b9 63 [2] 9d 6d [2] b6 41 [2] 98 63 [2] 8c 78 [2] 83 62 [2] 9d 7f [2] 9f 7e [2] 84 78 [2] 98 7f [2] 84 50 }

  condition:
    any of them
}