rule TTP_XOR_QUAD_CurrentVersionRun_59da {
  strings:
    $key_59da = { 0a b5 [2] 2e bb [2] 05 97 [2] 2b b5 [2] 3f ae [2] 30 b4 [2] 2e a9 [2] 2c a8 [2] 37 ae [2] 2b a9 [2] 37 86 }

  condition:
    any of them
}