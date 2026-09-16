rule TTP_XOR_QUAD_CurrentVersionRun_3cf5 {
  strings:
    $key_3cf5 = { 6f 9a [2] 4b 94 [2] 60 b8 [2] 4e 9a [2] 5a 81 [2] 55 9b [2] 4b 86 [2] 49 87 [2] 52 81 [2] 4e 86 [2] 52 a9 }

  condition:
    any of them
}