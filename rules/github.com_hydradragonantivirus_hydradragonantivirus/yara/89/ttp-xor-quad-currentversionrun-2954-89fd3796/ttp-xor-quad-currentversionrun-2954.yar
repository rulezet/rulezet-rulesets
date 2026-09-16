rule TTP_XOR_QUAD_CurrentVersionRun_2954 {
  strings:
    $key_2954 = { 7a 3b [2] 5e 35 [2] 75 19 [2] 5b 3b [2] 4f 20 [2] 40 3a [2] 5e 27 [2] 5c 26 [2] 47 20 [2] 5b 27 [2] 47 08 }

  condition:
    any of them
}