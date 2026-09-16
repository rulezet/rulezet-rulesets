rule TTP_XOR_QUAD_CurrentVersionRun_287f {
  strings:
    $key_287f = { 7b 10 [2] 5f 1e [2] 74 32 [2] 5a 10 [2] 4e 0b [2] 41 11 [2] 5f 0c [2] 5d 0d [2] 46 0b [2] 5a 0c [2] 46 23 }

  condition:
    any of them
}