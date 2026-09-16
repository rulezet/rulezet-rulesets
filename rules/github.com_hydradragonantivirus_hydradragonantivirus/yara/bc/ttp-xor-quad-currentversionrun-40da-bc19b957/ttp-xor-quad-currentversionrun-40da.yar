rule TTP_XOR_QUAD_CurrentVersionRun_40da {
  strings:
    $key_40da = { 13 b5 [2] 37 bb [2] 1c 97 [2] 32 b5 [2] 26 ae [2] 29 b4 [2] 37 a9 [2] 35 a8 [2] 2e ae [2] 32 a9 [2] 2e 86 }

  condition:
    any of them
}