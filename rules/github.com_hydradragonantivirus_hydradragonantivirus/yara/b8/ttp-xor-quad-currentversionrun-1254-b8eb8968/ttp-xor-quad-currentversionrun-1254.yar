rule TTP_XOR_QUAD_CurrentVersionRun_1254 {
  strings:
    $key_1254 = { 41 3b [2] 65 35 [2] 4e 19 [2] 60 3b [2] 74 20 [2] 7b 3a [2] 65 27 [2] 67 26 [2] 7c 20 [2] 60 27 [2] 7c 08 }

  condition:
    any of them
}