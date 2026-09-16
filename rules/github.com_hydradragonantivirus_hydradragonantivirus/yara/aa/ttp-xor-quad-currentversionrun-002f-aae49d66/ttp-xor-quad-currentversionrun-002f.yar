rule TTP_XOR_QUAD_CurrentVersionRun_002f {
  strings:
    $key_002f = { 53 40 [2] 77 4e [2] 5c 62 [2] 72 40 [2] 66 5b [2] 69 41 [2] 77 5c [2] 75 5d [2] 6e 5b [2] 72 5c [2] 6e 73 }

  condition:
    any of them
}