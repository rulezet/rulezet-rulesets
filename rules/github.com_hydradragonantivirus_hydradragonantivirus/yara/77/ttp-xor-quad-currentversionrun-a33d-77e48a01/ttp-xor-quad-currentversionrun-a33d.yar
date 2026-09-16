rule TTP_XOR_QUAD_CurrentVersionRun_a33d {
  strings:
    $key_a33d = { f0 52 [2] d4 5c [2] ff 70 [2] d1 52 [2] c5 49 [2] ca 53 [2] d4 4e [2] d6 4f [2] cd 49 [2] d1 4e [2] cd 61 }

  condition:
    any of them
}