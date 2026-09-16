rule TTP_XOR_QUAD_CurrentVersionRun_497f {
  strings:
    $key_497f = { 1a 10 [2] 3e 1e [2] 15 32 [2] 3b 10 [2] 2f 0b [2] 20 11 [2] 3e 0c [2] 3c 0d [2] 27 0b [2] 3b 0c [2] 27 23 }

  condition:
    any of them
}