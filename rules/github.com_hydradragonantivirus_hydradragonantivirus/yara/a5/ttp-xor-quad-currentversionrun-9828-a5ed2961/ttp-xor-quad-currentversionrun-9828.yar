rule TTP_XOR_QUAD_CurrentVersionRun_9828 {
  strings:
    $key_9828 = { cb 47 [2] ef 49 [2] c4 65 [2] ea 47 [2] fe 5c [2] f1 46 [2] ef 5b [2] ed 5a [2] f6 5c [2] ea 5b [2] f6 74 }

  condition:
    any of them
}