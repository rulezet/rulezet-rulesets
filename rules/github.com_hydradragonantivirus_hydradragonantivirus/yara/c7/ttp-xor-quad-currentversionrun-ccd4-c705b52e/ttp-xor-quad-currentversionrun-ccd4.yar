rule TTP_XOR_QUAD_CurrentVersionRun_ccd4 {
  strings:
    $key_ccd4 = { 9f bb [2] bb b5 [2] 90 99 [2] be bb [2] aa a0 [2] a5 ba [2] bb a7 [2] b9 a6 [2] a2 a0 [2] be a7 [2] a2 88 }

  condition:
    any of them
}