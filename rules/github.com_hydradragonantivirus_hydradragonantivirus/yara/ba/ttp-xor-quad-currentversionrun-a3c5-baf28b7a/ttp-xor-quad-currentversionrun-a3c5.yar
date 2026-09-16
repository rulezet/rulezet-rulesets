rule TTP_XOR_QUAD_CurrentVersionRun_a3c5 {
  strings:
    $key_a3c5 = { f0 aa [2] d4 a4 [2] ff 88 [2] d1 aa [2] c5 b1 [2] ca ab [2] d4 b6 [2] d6 b7 [2] cd b1 [2] d1 b6 [2] cd 99 }

  condition:
    any of them
}