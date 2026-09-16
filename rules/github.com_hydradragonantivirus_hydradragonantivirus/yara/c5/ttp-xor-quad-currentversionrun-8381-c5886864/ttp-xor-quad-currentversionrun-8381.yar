rule TTP_XOR_QUAD_CurrentVersionRun_8381 {
  strings:
    $key_8381 = { d0 ee [2] f4 e0 [2] df cc [2] f1 ee [2] e5 f5 [2] ea ef [2] f4 f2 [2] f6 f3 [2] ed f5 [2] f1 f2 [2] ed dd }

  condition:
    any of them
}