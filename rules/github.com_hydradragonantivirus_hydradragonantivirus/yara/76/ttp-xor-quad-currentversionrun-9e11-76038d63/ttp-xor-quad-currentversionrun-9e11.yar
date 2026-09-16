rule TTP_XOR_QUAD_CurrentVersionRun_9e11 {
  strings:
    $key_9e11 = { cd 7e [2] e9 70 [2] c2 5c [2] ec 7e [2] f8 65 [2] f7 7f [2] e9 62 [2] eb 63 [2] f0 65 [2] ec 62 [2] f0 4d }

  condition:
    any of them
}