rule TTP_XOR_QUAD_CurrentVersionRun_924e {
  strings:
    $key_924e = { c1 21 [2] e5 2f [2] ce 03 [2] e0 21 [2] f4 3a [2] fb 20 [2] e5 3d [2] e7 3c [2] fc 3a [2] e0 3d [2] fc 12 }

  condition:
    any of them
}