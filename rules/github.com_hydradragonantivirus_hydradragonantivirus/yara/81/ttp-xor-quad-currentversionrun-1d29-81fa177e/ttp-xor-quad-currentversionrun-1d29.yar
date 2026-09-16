rule TTP_XOR_QUAD_CurrentVersionRun_1d29 {
  strings:
    $key_1d29 = { 4e 46 [2] 6a 48 [2] 41 64 [2] 6f 46 [2] 7b 5d [2] 74 47 [2] 6a 5a [2] 68 5b [2] 73 5d [2] 6f 5a [2] 73 75 }

  condition:
    any of them
}