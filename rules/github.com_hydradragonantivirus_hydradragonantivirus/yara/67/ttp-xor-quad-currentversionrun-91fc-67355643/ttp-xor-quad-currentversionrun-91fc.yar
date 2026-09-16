rule TTP_XOR_QUAD_CurrentVersionRun_91fc {
  strings:
    $key_91fc = { c2 93 [2] e6 9d [2] cd b1 [2] e3 93 [2] f7 88 [2] f8 92 [2] e6 8f [2] e4 8e [2] ff 88 [2] e3 8f [2] ff a0 }

  condition:
    any of them
}