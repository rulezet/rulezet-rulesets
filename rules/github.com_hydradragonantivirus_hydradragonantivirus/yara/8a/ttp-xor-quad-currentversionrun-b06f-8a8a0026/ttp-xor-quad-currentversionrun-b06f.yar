rule TTP_XOR_QUAD_CurrentVersionRun_b06f {
  strings:
    $key_b06f = { e3 00 [2] c7 0e [2] ec 22 [2] c2 00 [2] d6 1b [2] d9 01 [2] c7 1c [2] c5 1d [2] de 1b [2] c2 1c [2] de 33 }

  condition:
    any of them
}