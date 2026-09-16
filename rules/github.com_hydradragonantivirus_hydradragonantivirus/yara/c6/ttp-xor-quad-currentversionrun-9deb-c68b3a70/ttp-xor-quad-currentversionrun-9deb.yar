rule TTP_XOR_QUAD_CurrentVersionRun_9deb {
  strings:
    $key_9deb = { ce 84 [2] ea 8a [2] c1 a6 [2] ef 84 [2] fb 9f [2] f4 85 [2] ea 98 [2] e8 99 [2] f3 9f [2] ef 98 [2] f3 b7 }

  condition:
    any of them
}