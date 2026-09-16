rule TTP_XOR_QUAD_CurrentVersionRun_9ee2 {
  strings:
    $key_9ee2 = { cd 8d [2] e9 83 [2] c2 af [2] ec 8d [2] f8 96 [2] f7 8c [2] e9 91 [2] eb 90 [2] f0 96 [2] ec 91 [2] f0 be }

  condition:
    any of them
}