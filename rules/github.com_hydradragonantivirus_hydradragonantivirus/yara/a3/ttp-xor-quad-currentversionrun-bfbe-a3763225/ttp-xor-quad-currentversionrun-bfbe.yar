rule TTP_XOR_QUAD_CurrentVersionRun_bfbe {
  strings:
    $key_bfbe = { ec d1 [2] c8 df [2] e3 f3 [2] cd d1 [2] d9 ca [2] d6 d0 [2] c8 cd [2] ca cc [2] d1 ca [2] cd cd [2] d1 e2 }

  condition:
    any of them
}