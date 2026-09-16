rule TTP_XOR_QUAD_CurrentVersionRun_282e {
  strings:
    $key_282e = { 7b 41 [2] 5f 4f [2] 74 63 [2] 5a 41 [2] 4e 5a [2] 41 40 [2] 5f 5d [2] 5d 5c [2] 46 5a [2] 5a 5d [2] 46 72 }

  condition:
    any of them
}