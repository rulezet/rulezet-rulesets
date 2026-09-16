rule TTP_XOR_QUAD_CurrentVersionRun_9e30 {
  strings:
    $key_9e30 = { cd 5f [2] e9 51 [2] c2 7d [2] ec 5f [2] f8 44 [2] f7 5e [2] e9 43 [2] eb 42 [2] f0 44 [2] ec 43 [2] f0 6c }

  condition:
    any of them
}