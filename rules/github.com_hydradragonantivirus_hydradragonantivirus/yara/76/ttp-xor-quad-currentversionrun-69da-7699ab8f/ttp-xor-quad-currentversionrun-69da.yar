rule TTP_XOR_QUAD_CurrentVersionRun_69da {
  strings:
    $key_69da = { 3a b5 [2] 1e bb [2] 35 97 [2] 1b b5 [2] 0f ae [2] 00 b4 [2] 1e a9 [2] 1c a8 [2] 07 ae [2] 1b a9 [2] 07 86 }

  condition:
    any of them
}