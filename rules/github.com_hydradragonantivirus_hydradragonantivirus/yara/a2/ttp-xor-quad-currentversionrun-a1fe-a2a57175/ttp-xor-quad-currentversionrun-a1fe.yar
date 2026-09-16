rule TTP_XOR_QUAD_CurrentVersionRun_a1fe {
  strings:
    $key_a1fe = { f2 91 [2] d6 9f [2] fd b3 [2] d3 91 [2] c7 8a [2] c8 90 [2] d6 8d [2] d4 8c [2] cf 8a [2] d3 8d [2] cf a2 }

  condition:
    any of them
}