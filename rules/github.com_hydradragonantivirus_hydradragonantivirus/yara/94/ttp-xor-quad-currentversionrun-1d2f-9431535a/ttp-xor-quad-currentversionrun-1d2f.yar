rule TTP_XOR_QUAD_CurrentVersionRun_1d2f {
  strings:
    $key_1d2f = { 4e 40 [2] 6a 4e [2] 41 62 [2] 6f 40 [2] 7b 5b [2] 74 41 [2] 6a 5c [2] 68 5d [2] 73 5b [2] 6f 5c [2] 73 73 }

  condition:
    any of them
}