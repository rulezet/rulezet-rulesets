rule TTP_XOR_QUAD_CurrentVersionRun_0ee5 {
  strings:
    $key_0ee5 = { 5d 8a [2] 79 84 [2] 52 a8 [2] 7c 8a [2] 68 91 [2] 67 8b [2] 79 96 [2] 7b 97 [2] 60 91 [2] 7c 96 [2] 60 b9 }

  condition:
    any of them
}