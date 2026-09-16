rule TTP_XOR_QUAD_CurrentVersionRun_9d3c {
  strings:
    $key_9d3c = { ce 53 [2] ea 5d [2] c1 71 [2] ef 53 [2] fb 48 [2] f4 52 [2] ea 4f [2] e8 4e [2] f3 48 [2] ef 4f [2] f3 60 }

  condition:
    any of them
}