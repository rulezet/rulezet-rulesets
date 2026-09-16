rule TTP_XOR_QUAD_CurrentVersionRun_b838 {
  strings:
    $key_b838 = { eb 57 [2] cf 59 [2] e4 75 [2] ca 57 [2] de 4c [2] d1 56 [2] cf 4b [2] cd 4a [2] d6 4c [2] ca 4b [2] d6 64 }

  condition:
    any of them
}