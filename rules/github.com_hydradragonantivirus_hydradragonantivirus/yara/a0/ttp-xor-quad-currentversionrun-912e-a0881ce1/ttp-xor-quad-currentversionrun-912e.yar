rule TTP_XOR_QUAD_CurrentVersionRun_912e {
  strings:
    $key_912e = { c2 41 [2] e6 4f [2] cd 63 [2] e3 41 [2] f7 5a [2] f8 40 [2] e6 5d [2] e4 5c [2] ff 5a [2] e3 5d [2] ff 72 }

  condition:
    any of them
}