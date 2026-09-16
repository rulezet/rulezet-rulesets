rule TTP_XOR_QUAD_CurrentVersionRun_327f {
  strings:
    $key_327f = { 61 10 [2] 45 1e [2] 6e 32 [2] 40 10 [2] 54 0b [2] 5b 11 [2] 45 0c [2] 47 0d [2] 5c 0b [2] 40 0c [2] 5c 23 }

  condition:
    any of them
}