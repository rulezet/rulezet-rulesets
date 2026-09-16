rule TTP_XOR_QUAD_CurrentVersionRun_ebda {
  strings:
    $key_ebda = { b8 b5 [2] 9c bb [2] b7 97 [2] 99 b5 [2] 8d ae [2] 82 b4 [2] 9c a9 [2] 9e a8 [2] 85 ae [2] 99 a9 [2] 85 86 }

  condition:
    any of them
}