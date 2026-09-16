rule TTP_XOR_QUAD_CurrentVersionRun_e554 {
  strings:
    $key_e554 = { b6 3b [2] 92 35 [2] b9 19 [2] 97 3b [2] 83 20 [2] 8c 3a [2] 92 27 [2] 90 26 [2] 8b 20 [2] 97 27 [2] 8b 08 }

  condition:
    any of them
}