rule TTP_XOR_QUAD_CurrentVersionRun_7934 {
  strings:
    $key_7934 = { 2a 5b [2] 0e 55 [2] 25 79 [2] 0b 5b [2] 1f 40 [2] 10 5a [2] 0e 47 [2] 0c 46 [2] 17 40 [2] 0b 47 [2] 17 68 }

  condition:
    any of them
}