rule TTP_XOR_QUAD_CurrentVersionRun_ed11 {
  strings:
    $key_ed11 = { be 7e [2] 9a 70 [2] b1 5c [2] 9f 7e [2] 8b 65 [2] 84 7f [2] 9a 62 [2] 98 63 [2] 83 65 [2] 9f 62 [2] 83 4d }

  condition:
    any of them
}