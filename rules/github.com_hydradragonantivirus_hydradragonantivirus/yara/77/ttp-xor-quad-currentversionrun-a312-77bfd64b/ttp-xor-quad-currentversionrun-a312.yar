rule TTP_XOR_QUAD_CurrentVersionRun_a312 {
  strings:
    $key_a312 = { f0 7d [2] d4 73 [2] ff 5f [2] d1 7d [2] c5 66 [2] ca 7c [2] d4 61 [2] d6 60 [2] cd 66 [2] d1 61 [2] cd 4e }

  condition:
    any of them
}