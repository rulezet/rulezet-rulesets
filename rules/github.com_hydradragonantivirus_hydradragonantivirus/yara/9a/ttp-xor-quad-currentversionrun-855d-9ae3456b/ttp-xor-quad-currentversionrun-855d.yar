rule TTP_XOR_QUAD_CurrentVersionRun_855d {
  strings:
    $key_855d = { d6 32 [2] f2 3c [2] d9 10 [2] f7 32 [2] e3 29 [2] ec 33 [2] f2 2e [2] f0 2f [2] eb 29 [2] f7 2e [2] eb 01 }

  condition:
    any of them
}