rule TTP_XOR_QUAD_CurrentVersionRun_5dda {
  strings:
    $key_5dda = { 0e b5 [2] 2a bb [2] 01 97 [2] 2f b5 [2] 3b ae [2] 34 b4 [2] 2a a9 [2] 28 a8 [2] 33 ae [2] 2f a9 [2] 33 86 }

  condition:
    any of them
}