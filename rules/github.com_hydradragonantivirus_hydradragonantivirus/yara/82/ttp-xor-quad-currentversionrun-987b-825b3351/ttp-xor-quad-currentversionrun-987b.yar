rule TTP_XOR_QUAD_CurrentVersionRun_987b {
  strings:
    $key_987b = { cb 14 [2] ef 1a [2] c4 36 [2] ea 14 [2] fe 0f [2] f1 15 [2] ef 08 [2] ed 09 [2] f6 0f [2] ea 08 [2] f6 27 }

  condition:
    any of them
}