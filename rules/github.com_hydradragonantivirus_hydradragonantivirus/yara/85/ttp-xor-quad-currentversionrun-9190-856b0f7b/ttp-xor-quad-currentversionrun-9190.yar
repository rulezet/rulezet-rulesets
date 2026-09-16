rule TTP_XOR_QUAD_CurrentVersionRun_9190 {
  strings:
    $key_9190 = { c2 ff [2] e6 f1 [2] cd dd [2] e3 ff [2] f7 e4 [2] f8 fe [2] e6 e3 [2] e4 e2 [2] ff e4 [2] e3 e3 [2] ff cc }

  condition:
    any of them
}