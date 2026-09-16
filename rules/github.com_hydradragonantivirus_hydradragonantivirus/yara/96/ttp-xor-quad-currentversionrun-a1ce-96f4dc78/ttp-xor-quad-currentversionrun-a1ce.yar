rule TTP_XOR_QUAD_CurrentVersionRun_a1ce {
  strings:
    $key_a1ce = { f2 a1 [2] d6 af [2] fd 83 [2] d3 a1 [2] c7 ba [2] c8 a0 [2] d6 bd [2] d4 bc [2] cf ba [2] d3 bd [2] cf 92 }

  condition:
    any of them
}