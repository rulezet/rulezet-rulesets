rule TTP_XOR_QUAD_CurrentVersionRun_ea76 {
  strings:
    $key_ea76 = { b9 19 [2] 9d 17 [2] b6 3b [2] 98 19 [2] 8c 02 [2] 83 18 [2] 9d 05 [2] 9f 04 [2] 84 02 [2] 98 05 [2] 84 2a }

  condition:
    any of them
}