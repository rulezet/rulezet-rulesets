rule TTP_XOR_QUAD_CurrentVersionRun_910e {
  strings:
    $key_910e = { c2 61 [2] e6 6f [2] cd 43 [2] e3 61 [2] f7 7a [2] f8 60 [2] e6 7d [2] e4 7c [2] ff 7a [2] e3 7d [2] ff 52 }

  condition:
    any of them
}