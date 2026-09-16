rule TTP_XOR_QUAD_CurrentVersionRun_911f {
  strings:
    $key_911f = { c2 70 [2] e6 7e [2] cd 52 [2] e3 70 [2] f7 6b [2] f8 71 [2] e6 6c [2] e4 6d [2] ff 6b [2] e3 6c [2] ff 43 }

  condition:
    any of them
}