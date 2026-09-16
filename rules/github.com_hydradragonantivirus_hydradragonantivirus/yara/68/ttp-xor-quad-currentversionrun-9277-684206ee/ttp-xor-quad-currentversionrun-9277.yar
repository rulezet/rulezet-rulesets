rule TTP_XOR_QUAD_CurrentVersionRun_9277 {
  strings:
    $key_9277 = { c1 18 [2] e5 16 [2] ce 3a [2] e0 18 [2] f4 03 [2] fb 19 [2] e5 04 [2] e7 05 [2] fc 03 [2] e0 04 [2] fc 2b }

  condition:
    any of them
}