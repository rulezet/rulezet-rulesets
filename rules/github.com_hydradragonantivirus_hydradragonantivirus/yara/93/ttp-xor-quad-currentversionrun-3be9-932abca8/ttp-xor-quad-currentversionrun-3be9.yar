rule TTP_XOR_QUAD_CurrentVersionRun_3be9 {
  strings:
    $key_3be9 = { 68 86 [2] 4c 88 [2] 67 a4 [2] 49 86 [2] 5d 9d [2] 52 87 [2] 4c 9a [2] 4e 9b [2] 55 9d [2] 49 9a [2] 55 b5 }

  condition:
    any of them
}