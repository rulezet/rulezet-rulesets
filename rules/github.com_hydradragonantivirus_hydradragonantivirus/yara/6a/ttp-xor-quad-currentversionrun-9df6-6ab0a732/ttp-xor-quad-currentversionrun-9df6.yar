rule TTP_XOR_QUAD_CurrentVersionRun_9df6 {
  strings:
    $key_9df6 = { ce 99 [2] ea 97 [2] c1 bb [2] ef 99 [2] fb 82 [2] f4 98 [2] ea 85 [2] e8 84 [2] f3 82 [2] ef 85 [2] f3 aa }

  condition:
    any of them
}