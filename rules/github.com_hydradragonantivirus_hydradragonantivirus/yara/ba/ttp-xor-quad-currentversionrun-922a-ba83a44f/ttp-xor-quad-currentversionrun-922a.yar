rule TTP_XOR_QUAD_CurrentVersionRun_922a {
  strings:
    $key_922a = { c1 45 [2] e5 4b [2] ce 67 [2] e0 45 [2] f4 5e [2] fb 44 [2] e5 59 [2] e7 58 [2] fc 5e [2] e0 59 [2] fc 76 }

  condition:
    any of them
}