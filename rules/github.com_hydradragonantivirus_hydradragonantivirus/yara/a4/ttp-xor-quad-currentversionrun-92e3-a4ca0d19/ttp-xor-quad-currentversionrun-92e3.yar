rule TTP_XOR_QUAD_CurrentVersionRun_92e3 {
  strings:
    $key_92e3 = { c1 8c [2] e5 82 [2] ce ae [2] e0 8c [2] f4 97 [2] fb 8d [2] e5 90 [2] e7 91 [2] fc 97 [2] e0 90 [2] fc bf }

  condition:
    any of them
}