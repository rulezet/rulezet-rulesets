rule TTP_XOR_QUAD_CurrentVersionRun_a34d {
  strings:
    $key_a34d = { f0 22 [2] d4 2c [2] ff 00 [2] d1 22 [2] c5 39 [2] ca 23 [2] d4 3e [2] d6 3f [2] cd 39 [2] d1 3e [2] cd 11 }

  condition:
    any of them
}