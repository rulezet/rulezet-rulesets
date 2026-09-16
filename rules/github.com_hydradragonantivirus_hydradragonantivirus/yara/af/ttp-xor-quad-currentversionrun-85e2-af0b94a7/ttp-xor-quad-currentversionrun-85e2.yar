rule TTP_XOR_QUAD_CurrentVersionRun_85e2 {
  strings:
    $key_85e2 = { d6 8d [2] f2 83 [2] d9 af [2] f7 8d [2] e3 96 [2] ec 8c [2] f2 91 [2] f0 90 [2] eb 96 [2] f7 91 [2] eb be }

  condition:
    any of them
}