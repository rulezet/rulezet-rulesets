rule TTP_XOR_QUAD_CurrentVersionRun_92e9 {
  strings:
    $key_92e9 = { c1 86 [2] e5 88 [2] ce a4 [2] e0 86 [2] f4 9d [2] fb 87 [2] e5 9a [2] e7 9b [2] fc 9d [2] e0 9a [2] fc b5 }

  condition:
    any of them
}