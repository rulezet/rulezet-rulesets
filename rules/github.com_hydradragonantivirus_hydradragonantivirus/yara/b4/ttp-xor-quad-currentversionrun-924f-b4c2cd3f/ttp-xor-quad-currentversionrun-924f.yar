rule TTP_XOR_QUAD_CurrentVersionRun_924f {
  strings:
    $key_924f = { c1 20 [2] e5 2e [2] ce 02 [2] e0 20 [2] f4 3b [2] fb 21 [2] e5 3c [2] e7 3d [2] fc 3b [2] e0 3c [2] fc 13 }

  condition:
    any of them
}