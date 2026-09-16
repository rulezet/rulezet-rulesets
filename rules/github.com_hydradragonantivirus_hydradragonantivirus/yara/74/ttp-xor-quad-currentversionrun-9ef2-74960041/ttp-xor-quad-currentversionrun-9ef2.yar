rule TTP_XOR_QUAD_CurrentVersionRun_9ef2 {
  strings:
    $key_9ef2 = { cd 9d [2] e9 93 [2] c2 bf [2] ec 9d [2] f8 86 [2] f7 9c [2] e9 81 [2] eb 80 [2] f0 86 [2] ec 81 [2] f0 ae }

  condition:
    any of them
}