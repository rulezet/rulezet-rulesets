rule TTP_XOR_QUAD_CurrentVersionRun_7dda {
  strings:
    $key_7dda = { 2e b5 [2] 0a bb [2] 21 97 [2] 0f b5 [2] 1b ae [2] 14 b4 [2] 0a a9 [2] 08 a8 [2] 13 ae [2] 0f a9 [2] 13 86 }

  condition:
    any of them
}