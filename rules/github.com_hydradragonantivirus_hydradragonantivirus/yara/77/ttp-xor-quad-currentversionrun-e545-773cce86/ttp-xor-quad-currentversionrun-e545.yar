rule TTP_XOR_QUAD_CurrentVersionRun_e545 {
  strings:
    $key_e545 = { b6 2a [2] 92 24 [2] b9 08 [2] 97 2a [2] 83 31 [2] 8c 2b [2] 92 36 [2] 90 37 [2] 8b 31 [2] 97 36 [2] 8b 19 }

  condition:
    any of them
}