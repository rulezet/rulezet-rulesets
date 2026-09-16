rule TTP_XOR_QUAD_CurrentVersionRun_9299 {
  strings:
    $key_9299 = { c1 f6 [2] e5 f8 [2] ce d4 [2] e0 f6 [2] f4 ed [2] fb f7 [2] e5 ea [2] e7 eb [2] fc ed [2] e0 ea [2] fc c5 }

  condition:
    any of them
}