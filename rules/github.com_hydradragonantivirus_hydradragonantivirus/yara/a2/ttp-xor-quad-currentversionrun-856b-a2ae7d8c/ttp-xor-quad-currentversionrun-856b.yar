rule TTP_XOR_QUAD_CurrentVersionRun_856b {
  strings:
    $key_856b = { d6 04 [2] f2 0a [2] d9 26 [2] f7 04 [2] e3 1f [2] ec 05 [2] f2 18 [2] f0 19 [2] eb 1f [2] f7 18 [2] eb 37 }

  condition:
    any of them
}