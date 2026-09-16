rule TTP_XOR_QUAD_CurrentVersionRun_d08c {
  strings:
    $key_d08c = { 83 e3 [2] a7 ed [2] 8c c1 [2] a2 e3 [2] b6 f8 [2] b9 e2 [2] a7 ff [2] a5 fe [2] be f8 [2] a2 ff [2] be d0 }

  condition:
    any of them
}