rule TTP_XOR_QUAD_CurrentVersionRun_9b8c {
  strings:
    $key_9b8c = { c8 e3 [2] ec ed [2] c7 c1 [2] e9 e3 [2] fd f8 [2] f2 e2 [2] ec ff [2] ee fe [2] f5 f8 [2] e9 ff [2] f5 d0 }

  condition:
    any of them
}