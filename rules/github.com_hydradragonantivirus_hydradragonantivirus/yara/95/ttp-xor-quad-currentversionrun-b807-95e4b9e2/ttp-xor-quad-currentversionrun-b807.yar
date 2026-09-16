rule TTP_XOR_QUAD_CurrentVersionRun_b807 {
  strings:
    $key_b807 = { eb 68 [2] cf 66 [2] e4 4a [2] ca 68 [2] de 73 [2] d1 69 [2] cf 74 [2] cd 75 [2] d6 73 [2] ca 74 [2] d6 5b }

  condition:
    any of them
}