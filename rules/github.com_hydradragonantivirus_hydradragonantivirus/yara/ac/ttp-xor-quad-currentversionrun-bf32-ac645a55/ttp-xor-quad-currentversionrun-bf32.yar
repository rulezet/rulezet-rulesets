rule TTP_XOR_QUAD_CurrentVersionRun_bf32 {
  strings:
    $key_bf32 = { ec 5d [2] c8 53 [2] e3 7f [2] cd 5d [2] d9 46 [2] d6 5c [2] c8 41 [2] ca 40 [2] d1 46 [2] cd 41 [2] d1 6e }

  condition:
    any of them
}