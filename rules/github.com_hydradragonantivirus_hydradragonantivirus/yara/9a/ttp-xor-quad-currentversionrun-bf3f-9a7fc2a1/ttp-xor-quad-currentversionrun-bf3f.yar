rule TTP_XOR_QUAD_CurrentVersionRun_bf3f {
  strings:
    $key_bf3f = { ec 50 [2] c8 5e [2] e3 72 [2] cd 50 [2] d9 4b [2] d6 51 [2] c8 4c [2] ca 4d [2] d1 4b [2] cd 4c [2] d1 63 }

  condition:
    any of them
}