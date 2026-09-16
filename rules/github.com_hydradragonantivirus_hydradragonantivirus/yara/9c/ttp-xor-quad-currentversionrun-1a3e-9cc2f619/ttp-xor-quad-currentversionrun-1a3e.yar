rule TTP_XOR_QUAD_CurrentVersionRun_1a3e {
  strings:
    $key_1a3e = { 49 51 [2] 6d 5f [2] 46 73 [2] 68 51 [2] 7c 4a [2] 73 50 [2] 6d 4d [2] 6f 4c [2] 74 4a [2] 68 4d [2] 74 62 }

  condition:
    any of them
}