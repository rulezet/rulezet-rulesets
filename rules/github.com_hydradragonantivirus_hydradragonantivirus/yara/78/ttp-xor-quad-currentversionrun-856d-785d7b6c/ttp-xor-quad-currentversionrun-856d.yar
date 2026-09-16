rule TTP_XOR_QUAD_CurrentVersionRun_856d {
  strings:
    $key_856d = { d6 02 [2] f2 0c [2] d9 20 [2] f7 02 [2] e3 19 [2] ec 03 [2] f2 1e [2] f0 1f [2] eb 19 [2] f7 1e [2] eb 31 }

  condition:
    any of them
}