rule TTP_XOR_QUAD_CurrentVersionRun_b07e {
  strings:
    $key_b07e = { e3 11 [2] c7 1f [2] ec 33 [2] c2 11 [2] d6 0a [2] d9 10 [2] c7 0d [2] c5 0c [2] de 0a [2] c2 0d [2] de 22 }

  condition:
    any of them
}