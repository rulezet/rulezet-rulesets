rule TTP_XOR_QUAD_CurrentVersionRun_98eb {
  strings:
    $key_98eb = { cb 84 [2] ef 8a [2] c4 a6 [2] ea 84 [2] fe 9f [2] f1 85 [2] ef 98 [2] ed 99 [2] f6 9f [2] ea 98 [2] f6 b7 }

  condition:
    any of them
}