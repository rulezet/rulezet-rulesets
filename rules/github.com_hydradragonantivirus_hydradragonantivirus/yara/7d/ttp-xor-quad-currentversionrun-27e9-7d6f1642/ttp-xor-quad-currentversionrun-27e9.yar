rule TTP_XOR_QUAD_CurrentVersionRun_27e9 {
  strings:
    $key_27e9 = { 74 86 [2] 50 88 [2] 7b a4 [2] 55 86 [2] 41 9d [2] 4e 87 [2] 50 9a [2] 52 9b [2] 49 9d [2] 55 9a [2] 49 b5 }

  condition:
    any of them
}