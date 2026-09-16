rule TTP_XOR_QUAD_CurrentVersionRun_920e {
  strings:
    $key_920e = { c1 61 [2] e5 6f [2] ce 43 [2] e0 61 [2] f4 7a [2] fb 60 [2] e5 7d [2] e7 7c [2] fc 7a [2] e0 7d [2] fc 52 }

  condition:
    any of them
}