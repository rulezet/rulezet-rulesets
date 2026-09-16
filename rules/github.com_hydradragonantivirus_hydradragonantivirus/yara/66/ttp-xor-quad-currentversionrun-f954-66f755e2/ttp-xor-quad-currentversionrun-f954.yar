rule TTP_XOR_QUAD_CurrentVersionRun_f954 {
  strings:
    $key_f954 = { aa 3b [2] 8e 35 [2] a5 19 [2] 8b 3b [2] 9f 20 [2] 90 3a [2] 8e 27 [2] 8c 26 [2] 97 20 [2] 8b 27 [2] 97 08 }

  condition:
    any of them
}