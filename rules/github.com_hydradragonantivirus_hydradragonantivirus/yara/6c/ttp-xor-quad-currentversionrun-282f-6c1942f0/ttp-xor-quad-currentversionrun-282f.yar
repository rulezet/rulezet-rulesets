rule TTP_XOR_QUAD_CurrentVersionRun_282f {
  strings:
    $key_282f = { 7b 40 [2] 5f 4e [2] 74 62 [2] 5a 40 [2] 4e 5b [2] 41 41 [2] 5f 5c [2] 5d 5d [2] 46 5b [2] 5a 5c [2] 46 73 }

  condition:
    any of them
}