rule TTP_XOR_QUAD_CurrentVersionRun_bf00 {
  strings:
    $key_bf00 = { ec 6f [2] c8 61 [2] e3 4d [2] cd 6f [2] d9 74 [2] d6 6e [2] c8 73 [2] ca 72 [2] d1 74 [2] cd 73 [2] d1 5c }

  condition:
    any of them
}