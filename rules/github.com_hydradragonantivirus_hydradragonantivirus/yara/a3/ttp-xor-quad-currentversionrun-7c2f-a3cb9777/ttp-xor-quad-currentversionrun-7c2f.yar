rule TTP_XOR_QUAD_CurrentVersionRun_7c2f {
  strings:
    $key_7c2f = { 2f 40 [2] 0b 4e [2] 20 62 [2] 0e 40 [2] 1a 5b [2] 15 41 [2] 0b 5c [2] 09 5d [2] 12 5b [2] 0e 5c [2] 12 73 }

  condition:
    any of them
}