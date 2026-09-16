rule TTP_XOR_QUAD_CurrentVersionRun_982d {
  strings:
    $key_982d = { cb 42 [2] ef 4c [2] c4 60 [2] ea 42 [2] fe 59 [2] f1 43 [2] ef 5e [2] ed 5f [2] f6 59 [2] ea 5e [2] f6 71 }

  condition:
    any of them
}