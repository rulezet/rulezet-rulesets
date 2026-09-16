rule TTP_XOR_QUAD_CurrentVersionRun_8384 {
  strings:
    $key_8384 = { d0 eb [2] f4 e5 [2] df c9 [2] f1 eb [2] e5 f0 [2] ea ea [2] f4 f7 [2] f6 f6 [2] ed f0 [2] f1 f7 [2] ed d8 }

  condition:
    any of them
}