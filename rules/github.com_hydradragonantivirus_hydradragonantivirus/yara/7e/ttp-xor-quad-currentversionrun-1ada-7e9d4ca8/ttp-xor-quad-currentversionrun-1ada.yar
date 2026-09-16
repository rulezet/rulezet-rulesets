rule TTP_XOR_QUAD_CurrentVersionRun_1ada {
  strings:
    $key_1ada = { 49 b5 [2] 6d bb [2] 46 97 [2] 68 b5 [2] 7c ae [2] 73 b4 [2] 6d a9 [2] 6f a8 [2] 74 ae [2] 68 a9 [2] 74 86 }

  condition:
    any of them
}