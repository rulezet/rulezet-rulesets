rule TTP_XOR_QUAD_CurrentVersionRun_bf20 {
  strings:
    $key_bf20 = { ec 4f [2] c8 41 [2] e3 6d [2] cd 4f [2] d9 54 [2] d6 4e [2] c8 53 [2] ca 52 [2] d1 54 [2] cd 53 [2] d1 7c }

  condition:
    any of them
}