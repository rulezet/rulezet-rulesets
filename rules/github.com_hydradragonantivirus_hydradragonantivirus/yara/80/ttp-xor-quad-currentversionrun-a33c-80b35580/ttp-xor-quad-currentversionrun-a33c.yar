rule TTP_XOR_QUAD_CurrentVersionRun_a33c {
  strings:
    $key_a33c = { f0 53 [2] d4 5d [2] ff 71 [2] d1 53 [2] c5 48 [2] ca 52 [2] d4 4f [2] d6 4e [2] cd 48 [2] d1 4f [2] cd 60 }

  condition:
    any of them
}