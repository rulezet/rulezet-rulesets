rule TTP_XOR_QUAD_CurrentVersionRun_982a {
  strings:
    $key_982a = { cb 45 [2] ef 4b [2] c4 67 [2] ea 45 [2] fe 5e [2] f1 44 [2] ef 59 [2] ed 58 [2] f6 5e [2] ea 59 [2] f6 76 }

  condition:
    any of them
}