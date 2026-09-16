rule TTP_XOR_QUAD_CurrentVersionRun_9101 {
  strings:
    $key_9101 = { c2 6e [2] e6 60 [2] cd 4c [2] e3 6e [2] f7 75 [2] f8 6f [2] e6 72 [2] e4 73 [2] ff 75 [2] e3 72 [2] ff 5d }

  condition:
    any of them
}