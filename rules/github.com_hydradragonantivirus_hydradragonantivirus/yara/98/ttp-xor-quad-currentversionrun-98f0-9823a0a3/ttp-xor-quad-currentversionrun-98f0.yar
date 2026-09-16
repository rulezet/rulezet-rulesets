rule TTP_XOR_QUAD_CurrentVersionRun_98f0 {
  strings:
    $key_98f0 = { cb 9f [2] ef 91 [2] c4 bd [2] ea 9f [2] fe 84 [2] f1 9e [2] ef 83 [2] ed 82 [2] f6 84 [2] ea 83 [2] f6 ac }

  condition:
    any of them
}