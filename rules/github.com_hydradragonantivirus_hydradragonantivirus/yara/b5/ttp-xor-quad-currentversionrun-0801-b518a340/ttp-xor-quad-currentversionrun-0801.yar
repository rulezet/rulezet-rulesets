rule TTP_XOR_QUAD_CurrentVersionRun_0801 {
  strings:
    $key_0801 = { 5b 6e [2] 7f 60 [2] 54 4c [2] 7a 6e [2] 6e 75 [2] 61 6f [2] 7f 72 [2] 7d 73 [2] 66 75 [2] 7a 72 [2] 66 5d }

  condition:
    any of them
}