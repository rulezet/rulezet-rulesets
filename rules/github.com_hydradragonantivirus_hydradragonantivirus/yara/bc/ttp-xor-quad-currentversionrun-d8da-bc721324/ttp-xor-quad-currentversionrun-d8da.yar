rule TTP_XOR_QUAD_CurrentVersionRun_d8da {
  strings:
    $key_d8da = { 8b b5 [2] af bb [2] 84 97 [2] aa b5 [2] be ae [2] b1 b4 [2] af a9 [2] ad a8 [2] b6 ae [2] aa a9 [2] b6 86 }

  condition:
    any of them
}