rule TTP_XOR_QUAD_CurrentVersionRun_852f {
  strings:
    $key_852f = { d6 40 [2] f2 4e [2] d9 62 [2] f7 40 [2] e3 5b [2] ec 41 [2] f2 5c [2] f0 5d [2] eb 5b [2] f7 5c [2] eb 73 }

  condition:
    any of them
}