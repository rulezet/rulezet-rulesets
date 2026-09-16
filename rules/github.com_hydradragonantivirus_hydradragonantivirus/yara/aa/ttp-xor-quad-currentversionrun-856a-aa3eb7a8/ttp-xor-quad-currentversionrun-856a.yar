rule TTP_XOR_QUAD_CurrentVersionRun_856a {
  strings:
    $key_856a = { d6 05 [2] f2 0b [2] d9 27 [2] f7 05 [2] e3 1e [2] ec 04 [2] f2 19 [2] f0 18 [2] eb 1e [2] f7 19 [2] eb 36 }

  condition:
    any of them
}