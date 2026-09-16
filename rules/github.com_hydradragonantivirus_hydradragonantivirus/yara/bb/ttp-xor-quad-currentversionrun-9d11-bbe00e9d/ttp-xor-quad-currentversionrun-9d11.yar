rule TTP_XOR_QUAD_CurrentVersionRun_9d11 {
  strings:
    $key_9d11 = { ce 7e [2] ea 70 [2] c1 5c [2] ef 7e [2] fb 65 [2] f4 7f [2] ea 62 [2] e8 63 [2] f3 65 [2] ef 62 [2] f3 4d }

  condition:
    any of them
}