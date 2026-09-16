rule TTP_XOR_QUAD_CurrentVersionRun_1dda {
  strings:
    $key_1dda = { 4e b5 [2] 6a bb [2] 41 97 [2] 6f b5 [2] 7b ae [2] 74 b4 [2] 6a a9 [2] 68 a8 [2] 73 ae [2] 6f a9 [2] 73 86 }

  condition:
    any of them
}