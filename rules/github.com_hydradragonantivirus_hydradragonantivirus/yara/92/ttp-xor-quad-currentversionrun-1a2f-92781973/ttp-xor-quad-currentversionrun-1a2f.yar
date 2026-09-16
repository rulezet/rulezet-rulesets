rule TTP_XOR_QUAD_CurrentVersionRun_1a2f {
  strings:
    $key_1a2f = { 49 40 [2] 6d 4e [2] 46 62 [2] 68 40 [2] 7c 5b [2] 73 41 [2] 6d 5c [2] 6f 5d [2] 74 5b [2] 68 5c [2] 74 73 }

  condition:
    any of them
}