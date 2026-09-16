rule TTP_XOR_QUAD_CurrentVersionRun_9215 {
  strings:
    $key_9215 = { c1 7a [2] e5 74 [2] ce 58 [2] e0 7a [2] f4 61 [2] fb 7b [2] e5 66 [2] e7 67 [2] fc 61 [2] e0 66 [2] fc 49 }

  condition:
    any of them
}