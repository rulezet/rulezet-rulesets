rule TTP_XOR_QUAD_CurrentVersionRun_851f {
  strings:
    $key_851f = { d6 70 [2] f2 7e [2] d9 52 [2] f7 70 [2] e3 6b [2] ec 71 [2] f2 6c [2] f0 6d [2] eb 6b [2] f7 6c [2] eb 43 }

  condition:
    any of them
}