rule TTP_XOR_QUAD_CurrentVersionRun_bf6f {
  strings:
    $key_bf6f = { ec 00 [2] c8 0e [2] e3 22 [2] cd 00 [2] d9 1b [2] d6 01 [2] c8 1c [2] ca 1d [2] d1 1b [2] cd 1c [2] d1 33 }

  condition:
    any of them
}