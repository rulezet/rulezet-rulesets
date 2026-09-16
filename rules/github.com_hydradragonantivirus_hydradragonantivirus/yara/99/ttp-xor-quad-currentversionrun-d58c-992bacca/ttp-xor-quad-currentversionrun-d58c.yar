rule TTP_XOR_QUAD_CurrentVersionRun_d58c {
  strings:
    $key_d58c = { 86 e3 [2] a2 ed [2] 89 c1 [2] a7 e3 [2] b3 f8 [2] bc e2 [2] a2 ff [2] a0 fe [2] bb f8 [2] a7 ff [2] bb d0 }

  condition:
    any of them
}