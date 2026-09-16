rule TTP_XOR_QUAD_CurrentVersionRun_b828 {
  strings:
    $key_b828 = { eb 47 [2] cf 49 [2] e4 65 [2] ca 47 [2] de 5c [2] d1 46 [2] cf 5b [2] cd 5a [2] d6 5c [2] ca 5b [2] d6 74 }

  condition:
    any of them
}