rule TTP_XOR_QUAD_CurrentVersionRun_ea11 {
  strings:
    $key_ea11 = { b9 7e [2] 9d 70 [2] b6 5c [2] 98 7e [2] 8c 65 [2] 83 7f [2] 9d 62 [2] 9f 63 [2] 84 65 [2] 98 62 [2] 84 4d }

  condition:
    any of them
}