rule TTP_XOR_QUAD_CurrentVersionRun_bf16 {
  strings:
    $key_bf16 = { ec 79 [2] c8 77 [2] e3 5b [2] cd 79 [2] d9 62 [2] d6 78 [2] c8 65 [2] ca 64 [2] d1 62 [2] cd 65 [2] d1 4a }

  condition:
    any of them
}