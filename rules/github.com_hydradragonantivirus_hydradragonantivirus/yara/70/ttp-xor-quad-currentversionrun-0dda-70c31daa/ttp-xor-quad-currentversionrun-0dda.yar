rule TTP_XOR_QUAD_CurrentVersionRun_0dda {
  strings:
    $key_0dda = { 5e b5 [2] 7a bb [2] 51 97 [2] 7f b5 [2] 6b ae [2] 64 b4 [2] 7a a9 [2] 78 a8 [2] 63 ae [2] 7f a9 [2] 63 86 }

  condition:
    any of them
}