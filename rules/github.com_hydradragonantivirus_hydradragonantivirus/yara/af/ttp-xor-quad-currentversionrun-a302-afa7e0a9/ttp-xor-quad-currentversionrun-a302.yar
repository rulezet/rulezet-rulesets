rule TTP_XOR_QUAD_CurrentVersionRun_a302 {
  strings:
    $key_a302 = { f0 6d [2] d4 63 [2] ff 4f [2] d1 6d [2] c5 76 [2] ca 6c [2] d4 71 [2] d6 70 [2] cd 76 [2] d1 71 [2] cd 5e }

  condition:
    any of them
}