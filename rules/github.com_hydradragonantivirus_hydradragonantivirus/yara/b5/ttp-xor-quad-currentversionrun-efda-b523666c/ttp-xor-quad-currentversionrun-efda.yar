rule TTP_XOR_QUAD_CurrentVersionRun_efda {
  strings:
    $key_efda = { bc b5 [2] 98 bb [2] b3 97 [2] 9d b5 [2] 89 ae [2] 86 b4 [2] 98 a9 [2] 9a a8 [2] 81 ae [2] 9d a9 [2] 81 86 }

  condition:
    any of them
}