rule TTP_XOR_QUAD_CurrentVersionRun_91fd {
  strings:
    $key_91fd = { c2 92 [2] e6 9c [2] cd b0 [2] e3 92 [2] f7 89 [2] f8 93 [2] e6 8e [2] e4 8f [2] ff 89 [2] e3 8e [2] ff a1 }

  condition:
    any of them
}