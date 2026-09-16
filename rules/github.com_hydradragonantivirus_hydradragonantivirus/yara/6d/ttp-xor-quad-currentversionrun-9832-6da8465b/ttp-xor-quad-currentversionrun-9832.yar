rule TTP_XOR_QUAD_CurrentVersionRun_9832 {
  strings:
    $key_9832 = { cb 5d [2] ef 53 [2] c4 7f [2] ea 5d [2] fe 46 [2] f1 5c [2] ef 41 [2] ed 40 [2] f6 46 [2] ea 41 [2] f6 6e }

  condition:
    any of them
}