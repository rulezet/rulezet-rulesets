rule TTP_XOR_QUAD_CurrentVersionRun_9eb1 {
  strings:
    $key_9eb1 = { cd de [2] e9 d0 [2] c2 fc [2] ec de [2] f8 c5 [2] f7 df [2] e9 c2 [2] eb c3 [2] f0 c5 [2] ec c2 [2] f0 ed }

  condition:
    any of them
}