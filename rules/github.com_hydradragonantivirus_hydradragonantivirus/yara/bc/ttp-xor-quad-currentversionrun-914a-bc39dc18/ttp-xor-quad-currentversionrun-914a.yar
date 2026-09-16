rule TTP_XOR_QUAD_CurrentVersionRun_914a {
  strings:
    $key_914a = { c2 25 [2] e6 2b [2] cd 07 [2] e3 25 [2] f7 3e [2] f8 24 [2] e6 39 [2] e4 38 [2] ff 3e [2] e3 39 [2] ff 16 }

  condition:
    any of them
}