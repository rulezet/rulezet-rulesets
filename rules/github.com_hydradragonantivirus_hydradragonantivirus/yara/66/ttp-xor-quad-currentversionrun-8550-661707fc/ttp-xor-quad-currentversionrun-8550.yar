rule TTP_XOR_QUAD_CurrentVersionRun_8550 {
  strings:
    $key_8550 = { d6 3f [2] f2 31 [2] d9 1d [2] f7 3f [2] e3 24 [2] ec 3e [2] f2 23 [2] f0 22 [2] eb 24 [2] f7 23 [2] eb 0c }

  condition:
    any of them
}