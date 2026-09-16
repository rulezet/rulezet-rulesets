rule TTP_XOR_QUAD_CurrentVersionRun_9ed2 {
  strings:
    $key_9ed2 = { cd bd [2] e9 b3 [2] c2 9f [2] ec bd [2] f8 a6 [2] f7 bc [2] e9 a1 [2] eb a0 [2] f0 a6 [2] ec a1 [2] f0 8e }

  condition:
    any of them
}