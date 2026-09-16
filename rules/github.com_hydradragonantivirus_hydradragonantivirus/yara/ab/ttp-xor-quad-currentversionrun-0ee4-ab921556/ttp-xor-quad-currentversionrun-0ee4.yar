rule TTP_XOR_QUAD_CurrentVersionRun_0ee4 {
  strings:
    $key_0ee4 = { 5d 8b [2] 79 85 [2] 52 a9 [2] 7c 8b [2] 68 90 [2] 67 8a [2] 79 97 [2] 7b 96 [2] 60 90 [2] 7c 97 [2] 60 b8 }

  condition:
    any of them
}