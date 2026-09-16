rule TTP_XOR_QUAD_CurrentVersionRun_ea24 {
  strings:
    $key_ea24 = { b9 4b [2] 9d 45 [2] b6 69 [2] 98 4b [2] 8c 50 [2] 83 4a [2] 9d 57 [2] 9f 56 [2] 84 50 [2] 98 57 [2] 84 78 }

  condition:
    any of them
}