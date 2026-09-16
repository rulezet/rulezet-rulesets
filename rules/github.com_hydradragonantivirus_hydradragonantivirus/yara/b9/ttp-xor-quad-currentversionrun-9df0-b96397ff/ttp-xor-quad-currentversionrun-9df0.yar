rule TTP_XOR_QUAD_CurrentVersionRun_9df0 {
  strings:
    $key_9df0 = { ce 9f [2] ea 91 [2] c1 bd [2] ef 9f [2] fb 84 [2] f4 9e [2] ea 83 [2] e8 82 [2] f3 84 [2] ef 83 [2] f3 ac }

  condition:
    any of them
}