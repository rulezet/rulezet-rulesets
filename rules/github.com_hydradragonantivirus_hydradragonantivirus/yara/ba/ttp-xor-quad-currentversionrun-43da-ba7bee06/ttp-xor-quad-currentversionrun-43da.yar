rule TTP_XOR_QUAD_CurrentVersionRun_43da {
  strings:
    $key_43da = { 10 b5 [2] 34 bb [2] 1f 97 [2] 31 b5 [2] 25 ae [2] 2a b4 [2] 34 a9 [2] 36 a8 [2] 2d ae [2] 31 a9 [2] 2d 86 }

  condition:
    any of them
}