rule TTP_XOR_QUAD_CurrentVersionRun_9e9f {
  strings:
    $key_9e9f = { cd f0 [2] e9 fe [2] c2 d2 [2] ec f0 [2] f8 eb [2] f7 f1 [2] e9 ec [2] eb ed [2] f0 eb [2] ec ec [2] f0 c3 }

  condition:
    any of them
}