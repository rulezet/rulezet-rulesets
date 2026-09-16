rule TTP_XOR_QUAD_CurrentVersionRun_a12f {
  strings:
    $key_a12f = { f2 40 [2] d6 4e [2] fd 62 [2] d3 40 [2] c7 5b [2] c8 41 [2] d6 5c [2] d4 5d [2] cf 5b [2] d3 5c [2] cf 73 }

  condition:
    any of them
}