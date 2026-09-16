rule TTP_XOR_QUAD_CurrentVersionRun_5d2f {
  strings:
    $key_5d2f = { 0e 40 [2] 2a 4e [2] 01 62 [2] 2f 40 [2] 3b 5b [2] 34 41 [2] 2a 5c [2] 28 5d [2] 33 5b [2] 2f 5c [2] 33 73 }

  condition:
    any of them
}