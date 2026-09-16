rule TTP_XOR_QUAD_CurrentVersionRun_a32a {
  strings:
    $key_a32a = { f0 45 [2] d4 4b [2] ff 67 [2] d1 45 [2] c5 5e [2] ca 44 [2] d4 59 [2] d6 58 [2] cd 5e [2] d1 59 [2] cd 76 }

  condition:
    any of them
}