rule TTP_XOR_QUAD_CurrentVersionRun_c08c {
  strings:
    $key_c08c = { 93 e3 [2] b7 ed [2] 9c c1 [2] b2 e3 [2] a6 f8 [2] a9 e2 [2] b7 ff [2] b5 fe [2] ae f8 [2] b2 ff [2] ae d0 }

  condition:
    any of them
}