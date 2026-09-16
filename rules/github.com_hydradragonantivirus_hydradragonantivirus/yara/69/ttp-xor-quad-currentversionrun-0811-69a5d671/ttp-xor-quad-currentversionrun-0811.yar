rule TTP_XOR_QUAD_CurrentVersionRun_0811 {
  strings:
    $key_0811 = { 5b 7e [2] 7f 70 [2] 54 5c [2] 7a 7e [2] 6e 65 [2] 61 7f [2] 7f 62 [2] 7d 63 [2] 66 65 [2] 7a 62 [2] 66 4d }

  condition:
    any of them
}