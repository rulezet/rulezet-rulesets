rule TTP_XOR_QUAD_CurrentVersionRun_9490 {
  strings:
    $key_9490 = { c7 ff [2] e3 f1 [2] c8 dd [2] e6 ff [2] f2 e4 [2] fd fe [2] e3 e3 [2] e1 e2 [2] fa e4 [2] e6 e3 [2] fa cc }

  condition:
    any of them
}