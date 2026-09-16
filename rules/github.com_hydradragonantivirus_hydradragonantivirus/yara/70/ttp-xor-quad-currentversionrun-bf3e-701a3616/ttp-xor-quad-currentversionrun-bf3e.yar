rule TTP_XOR_QUAD_CurrentVersionRun_bf3e {
  strings:
    $key_bf3e = { ec 51 [2] c8 5f [2] e3 73 [2] cd 51 [2] d9 4a [2] d6 50 [2] c8 4d [2] ca 4c [2] d1 4a [2] cd 4d [2] d1 62 }

  condition:
    any of them
}