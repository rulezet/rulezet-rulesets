rule TTP_XOR_QUAD_CurrentVersionRun_2dda {
  strings:
    $key_2dda = { 7e b5 [2] 5a bb [2] 71 97 [2] 5f b5 [2] 4b ae [2] 44 b4 [2] 5a a9 [2] 58 a8 [2] 43 ae [2] 5f a9 [2] 43 86 }

  condition:
    any of them
}