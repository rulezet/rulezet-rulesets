rule TTP_XOR_QUAD_CurrentVersionRun_c791 {
  strings:
    $key_c791 = { 94 fe [2] b0 f0 [2] 9b dc [2] b5 fe [2] a1 e5 [2] ae ff [2] b0 e2 [2] b2 e3 [2] a9 e5 [2] b5 e2 [2] a9 cd }

  condition:
    any of them
}