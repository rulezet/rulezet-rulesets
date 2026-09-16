rule TTP_XOR_QUAD_CurrentVersionRun_a328 {
  strings:
    $key_a328 = { f0 47 [2] d4 49 [2] ff 65 [2] d1 47 [2] c5 5c [2] ca 46 [2] d4 5b [2] d6 5a [2] cd 5c [2] d1 5b [2] cd 74 }

  condition:
    any of them
}