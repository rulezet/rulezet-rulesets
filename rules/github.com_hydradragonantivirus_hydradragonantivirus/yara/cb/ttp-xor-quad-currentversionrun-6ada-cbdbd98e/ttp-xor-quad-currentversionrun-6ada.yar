rule TTP_XOR_QUAD_CurrentVersionRun_6ada {
  strings:
    $key_6ada = { 39 b5 [2] 1d bb [2] 36 97 [2] 18 b5 [2] 0c ae [2] 03 b4 [2] 1d a9 [2] 1f a8 [2] 04 ae [2] 18 a9 [2] 04 86 }

  condition:
    any of them
}