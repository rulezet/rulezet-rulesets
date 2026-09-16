rule TTP_XOR_QUAD_CurrentVersionRun_853d {
  strings:
    $key_853d = { d6 52 [2] f2 5c [2] d9 70 [2] f7 52 [2] e3 49 [2] ec 53 [2] f2 4e [2] f0 4f [2] eb 49 [2] f7 4e [2] eb 61 }

  condition:
    any of them
}