rule TTP_XOR_QUAD_CurrentVersionRun_0ee9 {
  strings:
    $key_0ee9 = { 5d 86 [2] 79 88 [2] 52 a4 [2] 7c 86 [2] 68 9d [2] 67 87 [2] 79 9a [2] 7b 9b [2] 60 9d [2] 7c 9a [2] 60 b5 }

  condition:
    any of them
}