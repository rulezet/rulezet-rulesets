rule TTP_XOR_QUAD_CurrentVersionRun_9690 {
  strings:
    $key_9690 = { c5 ff [2] e1 f1 [2] ca dd [2] e4 ff [2] f0 e4 [2] ff fe [2] e1 e3 [2] e3 e2 [2] f8 e4 [2] e4 e3 [2] f8 cc }

  condition:
    any of them
}