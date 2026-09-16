rule TTP_XOR_QUAD_CurrentVersionRun_aeda {
  strings:
    $key_aeda = { fd b5 [2] d9 bb [2] f2 97 [2] dc b5 [2] c8 ae [2] c7 b4 [2] d9 a9 [2] db a8 [2] c0 ae [2] dc a9 [2] c0 86 }

  condition:
    any of them
}