rule TTP_XOR_QUAD_CurrentVersionRun_a14f {
  strings:
    $key_a14f = { f2 20 [2] d6 2e [2] fd 02 [2] d3 20 [2] c7 3b [2] c8 21 [2] d6 3c [2] d4 3d [2] cf 3b [2] d3 3c [2] cf 13 }

  condition:
    any of them
}