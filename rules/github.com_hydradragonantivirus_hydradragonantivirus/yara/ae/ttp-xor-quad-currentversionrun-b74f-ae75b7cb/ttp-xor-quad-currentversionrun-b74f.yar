rule TTP_XOR_QUAD_CurrentVersionRun_b74f {
  strings:
    $key_b74f = { e4 20 [2] c0 2e [2] eb 02 [2] c5 20 [2] d1 3b [2] de 21 [2] c0 3c [2] c2 3d [2] d9 3b [2] c5 3c [2] d9 13 }

  condition:
    any of them
}