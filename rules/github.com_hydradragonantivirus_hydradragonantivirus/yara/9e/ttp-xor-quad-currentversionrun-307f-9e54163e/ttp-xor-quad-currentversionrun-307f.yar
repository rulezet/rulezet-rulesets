rule TTP_XOR_QUAD_CurrentVersionRun_307f {
  strings:
    $key_307f = { 63 10 [2] 47 1e [2] 6c 32 [2] 42 10 [2] 56 0b [2] 59 11 [2] 47 0c [2] 45 0d [2] 5e 0b [2] 42 0c [2] 5e 23 }

  condition:
    any of them
}