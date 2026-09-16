rule TTP_XOR_QUAD_CurrentVersionRun_9199 {
  strings:
    $key_9199 = { c2 f6 [2] e6 f8 [2] cd d4 [2] e3 f6 [2] f7 ed [2] f8 f7 [2] e6 ea [2] e4 eb [2] ff ed [2] e3 ea [2] ff c5 }

  condition:
    any of them
}