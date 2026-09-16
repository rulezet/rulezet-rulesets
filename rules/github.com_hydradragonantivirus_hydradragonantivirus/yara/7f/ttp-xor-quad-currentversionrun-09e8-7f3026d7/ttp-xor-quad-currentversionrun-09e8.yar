rule TTP_XOR_QUAD_CurrentVersionRun_09e8 {
  strings:
    $key_09e8 = { 5a 87 [2] 7e 89 [2] 55 a5 [2] 7b 87 [2] 6f 9c [2] 60 86 [2] 7e 9b [2] 7c 9a [2] 67 9c [2] 7b 9b [2] 67 b4 }

  condition:
    any of them
}