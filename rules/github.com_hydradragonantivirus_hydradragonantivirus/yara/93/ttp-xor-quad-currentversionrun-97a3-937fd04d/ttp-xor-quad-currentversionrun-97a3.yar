rule TTP_XOR_QUAD_CurrentVersionRun_97a3 {
  strings:
    $key_97a3 = { c4 cc [2] e0 c2 [2] cb ee [2] e5 cc [2] f1 d7 [2] fe cd [2] e0 d0 [2] e2 d1 [2] f9 d7 [2] e5 d0 [2] f9 ff }

  condition:
    any of them
}