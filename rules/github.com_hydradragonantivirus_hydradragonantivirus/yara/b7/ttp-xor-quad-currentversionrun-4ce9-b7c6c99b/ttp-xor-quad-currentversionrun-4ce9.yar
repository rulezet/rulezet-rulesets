rule TTP_XOR_QUAD_CurrentVersionRun_4ce9 {
  strings:
    $key_4ce9 = { 1f 86 [2] 3b 88 [2] 10 a4 [2] 3e 86 [2] 2a 9d [2] 25 87 [2] 3b 9a [2] 39 9b [2] 22 9d [2] 3e 9a [2] 22 b5 }

  condition:
    any of them
}