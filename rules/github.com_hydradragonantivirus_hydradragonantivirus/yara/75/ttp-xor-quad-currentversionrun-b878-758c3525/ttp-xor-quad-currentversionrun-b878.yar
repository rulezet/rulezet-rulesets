rule TTP_XOR_QUAD_CurrentVersionRun_b878 {
  strings:
    $key_b878 = { eb 17 [2] cf 19 [2] e4 35 [2] ca 17 [2] de 0c [2] d1 16 [2] cf 0b [2] cd 0a [2] d6 0c [2] ca 0b [2] d6 24 }

  condition:
    any of them
}