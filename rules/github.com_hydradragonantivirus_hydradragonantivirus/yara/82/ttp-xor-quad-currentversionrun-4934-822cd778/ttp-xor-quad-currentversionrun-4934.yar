rule TTP_XOR_QUAD_CurrentVersionRun_4934 {
  strings:
    $key_4934 = { 1a 5b [2] 3e 55 [2] 15 79 [2] 3b 5b [2] 2f 40 [2] 20 5a [2] 3e 47 [2] 3c 46 [2] 27 40 [2] 3b 47 [2] 27 68 }

  condition:
    any of them
}