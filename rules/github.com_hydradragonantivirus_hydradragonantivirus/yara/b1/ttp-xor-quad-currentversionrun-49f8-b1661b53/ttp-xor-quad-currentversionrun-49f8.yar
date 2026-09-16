rule TTP_XOR_QUAD_CurrentVersionRun_49f8 {
  strings:
    $key_49f8 = { 1a 97 [2] 3e 99 [2] 15 b5 [2] 3b 97 [2] 2f 8c [2] 20 96 [2] 3e 8b [2] 3c 8a [2] 27 8c [2] 3b 8b [2] 27 a4 }

  condition:
    any of them
}