rule TTP_XOR_QUAD_CurrentVersionRun_d09f {
  strings:
    $key_d09f = { 83 f0 [2] a7 fe [2] 8c d2 [2] a2 f0 [2] b6 eb [2] b9 f1 [2] a7 ec [2] a5 ed [2] be eb [2] a2 ec [2] be c3 }

  condition:
    any of them
}