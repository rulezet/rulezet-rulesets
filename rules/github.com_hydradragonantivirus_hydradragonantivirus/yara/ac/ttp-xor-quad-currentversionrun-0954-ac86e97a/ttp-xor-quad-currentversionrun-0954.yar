rule TTP_XOR_QUAD_CurrentVersionRun_0954 {
  strings:
    $key_0954 = { 5a 3b [2] 7e 35 [2] 55 19 [2] 7b 3b [2] 6f 20 [2] 60 3a [2] 7e 27 [2] 7c 26 [2] 67 20 [2] 7b 27 [2] 67 08 }

  condition:
    any of them
}