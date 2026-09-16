rule TTP_XOR_QUAD_CurrentVersionRun_985b {
  strings:
    $key_985b = { cb 34 [2] ef 3a [2] c4 16 [2] ea 34 [2] fe 2f [2] f1 35 [2] ef 28 [2] ed 29 [2] f6 2f [2] ea 28 [2] f6 07 }

  condition:
    any of them
}