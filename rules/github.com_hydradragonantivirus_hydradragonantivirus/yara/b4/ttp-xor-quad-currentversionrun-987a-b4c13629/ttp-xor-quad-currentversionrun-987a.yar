rule TTP_XOR_QUAD_CurrentVersionRun_987a {
  strings:
    $key_987a = { cb 15 [2] ef 1b [2] c4 37 [2] ea 15 [2] fe 0e [2] f1 14 [2] ef 09 [2] ed 08 [2] f6 0e [2] ea 09 [2] f6 26 }

  condition:
    any of them
}