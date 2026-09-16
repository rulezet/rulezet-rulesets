rule TTP_XOR_QUAD_CurrentVersionRun_8517 {
  strings:
    $key_8517 = { d6 78 [2] f2 76 [2] d9 5a [2] f7 78 [2] e3 63 [2] ec 79 [2] f2 64 [2] f0 65 [2] eb 63 [2] f7 64 [2] eb 4b }

  condition:
    any of them
}