rule TTP_XOR_QUAD_CurrentVersionRun_9d3e {
  strings:
    $key_9d3e = { ce 51 [2] ea 5f [2] c1 73 [2] ef 51 [2] fb 4a [2] f4 50 [2] ea 4d [2] e8 4c [2] f3 4a [2] ef 4d [2] f3 62 }

  condition:
    any of them
}