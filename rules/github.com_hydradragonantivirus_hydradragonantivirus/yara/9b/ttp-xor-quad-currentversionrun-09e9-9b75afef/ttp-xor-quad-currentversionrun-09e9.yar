rule TTP_XOR_QUAD_CurrentVersionRun_09e9 {
  strings:
    $key_09e9 = { 5a 86 [2] 7e 88 [2] 55 a4 [2] 7b 86 [2] 6f 9d [2] 60 87 [2] 7e 9a [2] 7c 9b [2] 67 9d [2] 7b 9a [2] 67 b5 }

  condition:
    any of them
}