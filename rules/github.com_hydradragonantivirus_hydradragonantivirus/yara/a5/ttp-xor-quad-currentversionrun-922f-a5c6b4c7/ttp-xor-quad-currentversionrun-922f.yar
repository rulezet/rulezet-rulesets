rule TTP_XOR_QUAD_CurrentVersionRun_922f {
  strings:
    $key_922f = { c1 40 [2] e5 4e [2] ce 62 [2] e0 40 [2] f4 5b [2] fb 41 [2] e5 5c [2] e7 5d [2] fc 5b [2] e0 5c [2] fc 73 }

  condition:
    any of them
}