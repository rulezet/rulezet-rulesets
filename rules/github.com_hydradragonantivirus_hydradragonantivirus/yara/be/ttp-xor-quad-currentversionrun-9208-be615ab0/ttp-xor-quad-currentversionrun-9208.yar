rule TTP_XOR_QUAD_CurrentVersionRun_9208 {
  strings:
    $key_9208 = { c1 67 [2] e5 69 [2] ce 45 [2] e0 67 [2] f4 7c [2] fb 66 [2] e5 7b [2] e7 7a [2] fc 7c [2] e0 7b [2] fc 54 }

  condition:
    any of them
}