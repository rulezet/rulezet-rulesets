rule TTP_XOR_QUAD_CurrentVersionRun_9d3d {
  strings:
    $key_9d3d = { ce 52 [2] ea 5c [2] c1 70 [2] ef 52 [2] fb 49 [2] f4 53 [2] ea 4e [2] e8 4f [2] f3 49 [2] ef 4e [2] f3 61 }

  condition:
    any of them
}