rule TTP_XOR_QUAD_CurrentVersionRun_9213 {
  strings:
    $key_9213 = { c1 7c [2] e5 72 [2] ce 5e [2] e0 7c [2] f4 67 [2] fb 7d [2] e5 60 [2] e7 61 [2] fc 67 [2] e0 60 [2] fc 4f }

  condition:
    any of them
}