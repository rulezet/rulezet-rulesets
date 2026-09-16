rule TTP_XOR_QUAD_CurrentVersionRun_9998 {
  strings:
    $key_9998 = { ca f7 [2] ee f9 [2] c5 d5 [2] eb f7 [2] ff ec [2] f0 f6 [2] ee eb [2] ec ea [2] f7 ec [2] eb eb [2] f7 c4 }

  condition:
    any of them
}