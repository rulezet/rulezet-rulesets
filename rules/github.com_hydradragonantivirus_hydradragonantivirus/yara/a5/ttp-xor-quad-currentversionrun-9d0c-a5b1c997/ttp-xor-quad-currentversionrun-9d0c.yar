rule TTP_XOR_QUAD_CurrentVersionRun_9d0c {
  strings:
    $key_9d0c = { ce 63 [2] ea 6d [2] c1 41 [2] ef 63 [2] fb 78 [2] f4 62 [2] ea 7f [2] e8 7e [2] f3 78 [2] ef 7f [2] f3 50 }

  condition:
    any of them
}