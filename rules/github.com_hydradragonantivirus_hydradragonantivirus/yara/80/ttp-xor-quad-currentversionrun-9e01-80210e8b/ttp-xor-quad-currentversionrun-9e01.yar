rule TTP_XOR_QUAD_CurrentVersionRun_9e01 {
  strings:
    $key_9e01 = { cd 6e [2] e9 60 [2] c2 4c [2] ec 6e [2] f8 75 [2] f7 6f [2] e9 72 [2] eb 73 [2] f0 75 [2] ec 72 [2] f0 5d }

  condition:
    any of them
}