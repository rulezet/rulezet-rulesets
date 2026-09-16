rule TTP_XOR_QUAD_CurrentVersionRun_bf22 {
  strings:
    $key_bf22 = { ec 4d [2] c8 43 [2] e3 6f [2] cd 4d [2] d9 56 [2] d6 4c [2] c8 51 [2] ca 50 [2] d1 56 [2] cd 51 [2] d1 7e }

  condition:
    any of them
}