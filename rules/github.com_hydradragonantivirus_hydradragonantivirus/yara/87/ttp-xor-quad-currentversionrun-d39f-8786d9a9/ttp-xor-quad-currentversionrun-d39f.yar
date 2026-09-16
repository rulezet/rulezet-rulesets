rule TTP_XOR_QUAD_CurrentVersionRun_d39f {
  strings:
    $key_d39f = { 80 f0 [2] a4 fe [2] 8f d2 [2] a1 f0 [2] b5 eb [2] ba f1 [2] a4 ec [2] a6 ed [2] bd eb [2] a1 ec [2] bd c3 }

  condition:
    any of them
}