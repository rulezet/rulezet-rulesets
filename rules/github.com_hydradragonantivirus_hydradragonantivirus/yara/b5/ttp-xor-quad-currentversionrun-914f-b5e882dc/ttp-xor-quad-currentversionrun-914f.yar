rule TTP_XOR_QUAD_CurrentVersionRun_914f {
  strings:
    $key_914f = { c2 20 [2] e6 2e [2] cd 02 [2] e3 20 [2] f7 3b [2] f8 21 [2] e6 3c [2] e4 3d [2] ff 3b [2] e3 3c [2] ff 13 }

  condition:
    any of them
}