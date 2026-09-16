rule TTP_XOR_QUAD_CurrentVersionRun_ea27 {
  strings:
    $key_ea27 = { b9 48 [2] 9d 46 [2] b6 6a [2] 98 48 [2] 8c 53 [2] 83 49 [2] 9d 54 [2] 9f 55 [2] 84 53 [2] 98 54 [2] 84 7b }

  condition:
    any of them
}