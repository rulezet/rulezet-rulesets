rule TTP_XOR_QUAD_CurrentVersionRun_e254 {
  strings:
    $key_e254 = { b1 3b [2] 95 35 [2] be 19 [2] 90 3b [2] 84 20 [2] 8b 3a [2] 95 27 [2] 97 26 [2] 8c 20 [2] 90 27 [2] 8c 08 }

  condition:
    any of them
}