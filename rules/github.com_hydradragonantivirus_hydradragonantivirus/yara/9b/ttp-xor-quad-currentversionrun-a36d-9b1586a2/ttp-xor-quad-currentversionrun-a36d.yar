rule TTP_XOR_QUAD_CurrentVersionRun_a36d {
  strings:
    $key_a36d = { f0 02 [2] d4 0c [2] ff 20 [2] d1 02 [2] c5 19 [2] ca 03 [2] d4 1e [2] d6 1f [2] cd 19 [2] d1 1e [2] cd 31 }

  condition:
    any of them
}