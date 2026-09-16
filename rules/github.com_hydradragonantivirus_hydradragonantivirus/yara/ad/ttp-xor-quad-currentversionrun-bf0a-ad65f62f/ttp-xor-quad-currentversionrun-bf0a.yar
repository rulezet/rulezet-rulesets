rule TTP_XOR_QUAD_CurrentVersionRun_bf0a {
  strings:
    $key_bf0a = { ec 65 [2] c8 6b [2] e3 47 [2] cd 65 [2] d9 7e [2] d6 64 [2] c8 79 [2] ca 78 [2] d1 7e [2] cd 79 [2] d1 56 }

  condition:
    any of them
}