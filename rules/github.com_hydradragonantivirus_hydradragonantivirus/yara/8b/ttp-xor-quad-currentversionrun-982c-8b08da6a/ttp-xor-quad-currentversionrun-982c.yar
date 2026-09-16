rule TTP_XOR_QUAD_CurrentVersionRun_982c {
  strings:
    $key_982c = { cb 43 [2] ef 4d [2] c4 61 [2] ea 43 [2] fe 58 [2] f1 42 [2] ef 5f [2] ed 5e [2] f6 58 [2] ea 5f [2] f6 70 }

  condition:
    any of them
}