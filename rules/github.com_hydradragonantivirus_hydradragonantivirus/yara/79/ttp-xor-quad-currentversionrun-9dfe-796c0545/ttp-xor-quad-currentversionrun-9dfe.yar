rule TTP_XOR_QUAD_CurrentVersionRun_9dfe {
  strings:
    $key_9dfe = { ce 91 [2] ea 9f [2] c1 b3 [2] ef 91 [2] fb 8a [2] f4 90 [2] ea 8d [2] e8 8c [2] f3 8a [2] ef 8d [2] f3 a2 }

  condition:
    any of them
}