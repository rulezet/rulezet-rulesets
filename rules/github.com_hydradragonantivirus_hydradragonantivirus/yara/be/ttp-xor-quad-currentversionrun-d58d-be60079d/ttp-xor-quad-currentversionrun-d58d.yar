rule TTP_XOR_QUAD_CurrentVersionRun_d58d {
  strings:
    $key_d58d = { 86 e2 [2] a2 ec [2] 89 c0 [2] a7 e2 [2] b3 f9 [2] bc e3 [2] a2 fe [2] a0 ff [2] bb f9 [2] a7 fe [2] bb d1 }

  condition:
    any of them
}