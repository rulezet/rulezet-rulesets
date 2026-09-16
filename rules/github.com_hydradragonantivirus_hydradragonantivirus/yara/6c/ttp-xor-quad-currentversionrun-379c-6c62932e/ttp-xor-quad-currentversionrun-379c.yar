rule TTP_XOR_QUAD_CurrentVersionRun_379c {
  strings:
    $key_379c = { 64 f3 [2] 40 fd [2] 6b d1 [2] 45 f3 [2] 51 e8 [2] 5e f2 [2] 40 ef [2] 42 ee [2] 59 e8 [2] 45 ef [2] 59 c0 }

  condition:
    any of them
}