rule TTP_XOR_QUAD_CurrentVersionRun_2ce9 {
  strings:
    $key_2ce9 = { 7f 86 [2] 5b 88 [2] 70 a4 [2] 5e 86 [2] 4a 9d [2] 45 87 [2] 5b 9a [2] 59 9b [2] 42 9d [2] 5e 9a [2] 42 b5 }

  condition:
    any of them
}