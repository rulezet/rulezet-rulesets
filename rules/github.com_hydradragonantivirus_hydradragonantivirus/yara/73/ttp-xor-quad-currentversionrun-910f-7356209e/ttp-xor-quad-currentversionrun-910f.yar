rule TTP_XOR_QUAD_CurrentVersionRun_910f {
  strings:
    $key_910f = { c2 60 [2] e6 6e [2] cd 42 [2] e3 60 [2] f7 7b [2] f8 61 [2] e6 7c [2] e4 7d [2] ff 7b [2] e3 7c [2] ff 53 }

  condition:
    any of them
}