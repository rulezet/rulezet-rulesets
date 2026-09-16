rule TTP_XOR_QUAD_CurrentVersionRun_a333 {
  strings:
    $key_a333 = { f0 5c [2] d4 52 [2] ff 7e [2] d1 5c [2] c5 47 [2] ca 5d [2] d4 40 [2] d6 41 [2] cd 47 [2] d1 40 [2] cd 6f }

  condition:
    any of them
}