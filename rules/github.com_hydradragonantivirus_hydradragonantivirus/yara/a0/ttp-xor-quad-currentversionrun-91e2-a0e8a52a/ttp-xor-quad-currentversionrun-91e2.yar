rule TTP_XOR_QUAD_CurrentVersionRun_91e2 {
  strings:
    $key_91e2 = { c2 8d [2] e6 83 [2] cd af [2] e3 8d [2] f7 96 [2] f8 8c [2] e6 91 [2] e4 90 [2] ff 96 [2] e3 91 [2] ff be }

  condition:
    any of them
}