rule TTP_XOR_QUAD_CurrentVersionRun_57da {
  strings:
    $key_57da = { 04 b5 [2] 20 bb [2] 0b 97 [2] 25 b5 [2] 31 ae [2] 3e b4 [2] 20 a9 [2] 22 a8 [2] 39 ae [2] 25 a9 [2] 39 86 }

  condition:
    any of them
}