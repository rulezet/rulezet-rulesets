rule TTP_XOR_QUAD_CurrentVersionRun_b73f {
  strings:
    $key_b73f = { e4 50 [2] c0 5e [2] eb 72 [2] c5 50 [2] d1 4b [2] de 51 [2] c0 4c [2] c2 4d [2] d9 4b [2] c5 4c [2] d9 63 }

  condition:
    any of them
}