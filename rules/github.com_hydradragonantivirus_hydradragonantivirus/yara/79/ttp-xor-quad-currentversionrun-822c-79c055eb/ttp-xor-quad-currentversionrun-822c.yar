rule TTP_XOR_QUAD_CurrentVersionRun_822c {
  strings:
    $key_822c = { d1 43 [2] f5 4d [2] de 61 [2] f0 43 [2] e4 58 [2] eb 42 [2] f5 5f [2] f7 5e [2] ec 58 [2] f0 5f [2] ec 70 }

  condition:
    any of them
}