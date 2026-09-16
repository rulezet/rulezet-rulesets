rule TTP_XOR_QUAD_CurrentVersionRun_ea05 {
  strings:
    $key_ea05 = { b9 6a [2] 9d 64 [2] b6 48 [2] 98 6a [2] 8c 71 [2] 83 6b [2] 9d 76 [2] 9f 77 [2] 84 71 [2] 98 76 [2] 84 59 }

  condition:
    any of them
}