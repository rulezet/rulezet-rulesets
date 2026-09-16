rule TTP_XOR_QUAD_CurrentVersionRun_9db8 {
  strings:
    $key_9db8 = { ce d7 [2] ea d9 [2] c1 f5 [2] ef d7 [2] fb cc [2] f4 d6 [2] ea cb [2] e8 ca [2] f3 cc [2] ef cb [2] f3 e4 }

  condition:
    any of them
}