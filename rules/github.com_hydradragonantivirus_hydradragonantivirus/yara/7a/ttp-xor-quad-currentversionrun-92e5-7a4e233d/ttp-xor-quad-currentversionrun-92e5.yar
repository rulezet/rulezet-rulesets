rule TTP_XOR_QUAD_CurrentVersionRun_92e5 {
  strings:
    $key_92e5 = { c1 8a [2] e5 84 [2] ce a8 [2] e0 8a [2] f4 91 [2] fb 8b [2] e5 96 [2] e7 97 [2] fc 91 [2] e0 96 [2] fc b9 }

  condition:
    any of them
}