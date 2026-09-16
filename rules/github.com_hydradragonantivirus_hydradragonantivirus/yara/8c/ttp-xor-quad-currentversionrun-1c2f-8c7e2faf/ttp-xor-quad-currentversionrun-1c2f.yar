rule TTP_XOR_QUAD_CurrentVersionRun_1c2f {
  strings:
    $key_1c2f = { 4f 40 [2] 6b 4e [2] 40 62 [2] 6e 40 [2] 7a 5b [2] 75 41 [2] 6b 5c [2] 69 5d [2] 72 5b [2] 6e 5c [2] 72 73 }

  condition:
    any of them
}