rule TTP_XOR_QUAD_CurrentVersionRun_30da {
  strings:
    $key_30da = { 63 b5 [2] 47 bb [2] 6c 97 [2] 42 b5 [2] 56 ae [2] 59 b4 [2] 47 a9 [2] 45 a8 [2] 5e ae [2] 42 a9 [2] 5e 86 }

  condition:
    any of them
}