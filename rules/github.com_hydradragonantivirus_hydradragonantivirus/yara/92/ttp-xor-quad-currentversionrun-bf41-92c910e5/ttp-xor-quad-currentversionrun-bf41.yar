rule TTP_XOR_QUAD_CurrentVersionRun_bf41 {
  strings:
    $key_bf41 = { ec 2e [2] c8 20 [2] e3 0c [2] cd 2e [2] d9 35 [2] d6 2f [2] c8 32 [2] ca 33 [2] d1 35 [2] cd 32 [2] d1 1d }

  condition:
    any of them
}