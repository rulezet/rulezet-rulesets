rule TTP_XOR_QUAD_CurrentVersionRun_bf71 {
  strings:
    $key_bf71 = { ec 1e [2] c8 10 [2] e3 3c [2] cd 1e [2] d9 05 [2] d6 1f [2] c8 02 [2] ca 03 [2] d1 05 [2] cd 02 [2] d1 2d }

  condition:
    any of them
}