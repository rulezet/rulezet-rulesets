rule TTP_XOR_QUAD_CurrentVersionRun_bf2a {
  strings:
    $key_bf2a = { ec 45 [2] c8 4b [2] e3 67 [2] cd 45 [2] d9 5e [2] d6 44 [2] c8 59 [2] ca 58 [2] d1 5e [2] cd 59 [2] d1 76 }

  condition:
    any of them
}