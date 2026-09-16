rule TTP_XOR_QUAD_CurrentVersionRun_ea04 {
  strings:
    $key_ea04 = { b9 6b [2] 9d 65 [2] b6 49 [2] 98 6b [2] 8c 70 [2] 83 6a [2] 9d 77 [2] 9f 76 [2] 84 70 [2] 98 77 [2] 84 58 }

  condition:
    any of them
}