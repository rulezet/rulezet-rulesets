rule TTP_XOR_QUAD_CurrentVersionRun_5534 {
  strings:
    $key_5534 = { 06 5b [2] 22 55 [2] 09 79 [2] 27 5b [2] 33 40 [2] 3c 5a [2] 22 47 [2] 20 46 [2] 3b 40 [2] 27 47 [2] 3b 68 }

  condition:
    any of them
}