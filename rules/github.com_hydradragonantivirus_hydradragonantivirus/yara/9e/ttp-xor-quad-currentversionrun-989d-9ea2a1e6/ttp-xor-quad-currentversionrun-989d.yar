rule TTP_XOR_QUAD_CurrentVersionRun_989d {
  strings:
    $key_989d = { cb f2 [2] ef fc [2] c4 d0 [2] ea f2 [2] fe e9 [2] f1 f3 [2] ef ee [2] ed ef [2] f6 e9 [2] ea ee [2] f6 c1 }

  condition:
    any of them
}