rule TTP_XOR_QUAD_CurrentVersionRun_98fb {
  strings:
    $key_98fb = { cb 94 [2] ef 9a [2] c4 b6 [2] ea 94 [2] fe 8f [2] f1 95 [2] ef 88 [2] ed 89 [2] f6 8f [2] ea 88 [2] f6 a7 }

  condition:
    any of them
}