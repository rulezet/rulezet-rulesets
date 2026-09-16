rule TTP_XOR_QUAD_CurrentVersionRun_ea08 {
  strings:
    $key_ea08 = { b9 67 [2] 9d 69 [2] b6 45 [2] 98 67 [2] 8c 7c [2] 83 66 [2] 9d 7b [2] 9f 7a [2] 84 7c [2] 98 7b [2] 84 54 }

  condition:
    any of them
}