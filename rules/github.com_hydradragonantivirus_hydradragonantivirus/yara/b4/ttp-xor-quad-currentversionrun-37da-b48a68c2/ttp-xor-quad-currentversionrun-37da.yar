rule TTP_XOR_QUAD_CurrentVersionRun_37da {
  strings:
    $key_37da = { 64 b5 [2] 40 bb [2] 6b 97 [2] 45 b5 [2] 51 ae [2] 5e b4 [2] 40 a9 [2] 42 a8 [2] 59 ae [2] 45 a9 [2] 59 86 }

  condition:
    any of them
}