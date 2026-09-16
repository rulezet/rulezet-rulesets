rule TTP_XOR_QUAD_CurrentVersionRun_bf6a {
  strings:
    $key_bf6a = { ec 05 [2] c8 0b [2] e3 27 [2] cd 05 [2] d9 1e [2] d6 04 [2] c8 19 [2] ca 18 [2] d1 1e [2] cd 19 [2] d1 36 }

  condition:
    any of them
}