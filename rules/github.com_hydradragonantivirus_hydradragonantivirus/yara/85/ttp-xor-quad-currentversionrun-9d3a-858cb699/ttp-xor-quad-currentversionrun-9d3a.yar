rule TTP_XOR_QUAD_CurrentVersionRun_9d3a {
  strings:
    $key_9d3a = { ce 55 [2] ea 5b [2] c1 77 [2] ef 55 [2] fb 4e [2] f4 54 [2] ea 49 [2] e8 48 [2] f3 4e [2] ef 49 [2] f3 66 }

  condition:
    any of them
}