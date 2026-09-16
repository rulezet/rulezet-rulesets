rule TTP_XOR_QUAD_CurrentVersionRun_85e3 {
  strings:
    $key_85e3 = { d6 8c [2] f2 82 [2] d9 ae [2] f7 8c [2] e3 97 [2] ec 8d [2] f2 90 [2] f0 91 [2] eb 97 [2] f7 90 [2] eb bf }

  condition:
    any of them
}