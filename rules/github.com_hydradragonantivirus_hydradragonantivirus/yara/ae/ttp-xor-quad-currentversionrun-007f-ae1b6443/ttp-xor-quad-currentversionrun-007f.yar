rule TTP_XOR_QUAD_CurrentVersionRun_007f {
  strings:
    $key_007f = { 53 10 [2] 77 1e [2] 5c 32 [2] 72 10 [2] 66 0b [2] 69 11 [2] 77 0c [2] 75 0d [2] 6e 0b [2] 72 0c [2] 6e 23 }

  condition:
    any of them
}