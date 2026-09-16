rule TTP_XOR_QUAD_CurrentVersionRun_a36f {
  strings:
    $key_a36f = { f0 00 [2] d4 0e [2] ff 22 [2] d1 00 [2] c5 1b [2] ca 01 [2] d4 1c [2] d6 1d [2] cd 1b [2] d1 1c [2] cd 33 }

  condition:
    any of them
}