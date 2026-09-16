rule TTP_XOR_QUAD_CurrentVersionRun_a32f {
  strings:
    $key_a32f = { f0 40 [2] d4 4e [2] ff 62 [2] d1 40 [2] c5 5b [2] ca 41 [2] d4 5c [2] d6 5d [2] cd 5b [2] d1 5c [2] cd 73 }

  condition:
    any of them
}