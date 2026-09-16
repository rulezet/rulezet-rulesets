rule TTP_XOR_QUAD_CurrentVersionRun_f9da {
  strings:
    $key_f9da = { aa b5 [2] 8e bb [2] a5 97 [2] 8b b5 [2] 9f ae [2] 90 b4 [2] 8e a9 [2] 8c a8 [2] 97 ae [2] 8b a9 [2] 97 86 }

  condition:
    any of them
}