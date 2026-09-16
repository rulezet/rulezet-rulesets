rule TTP_XOR_QUAD_CurrentVersionRun_b816 {
  strings:
    $key_b816 = { eb 79 [2] cf 77 [2] e4 5b [2] ca 79 [2] de 62 [2] d1 78 [2] cf 65 [2] cd 64 [2] d6 62 [2] ca 65 [2] d6 4a }

  condition:
    any of them
}