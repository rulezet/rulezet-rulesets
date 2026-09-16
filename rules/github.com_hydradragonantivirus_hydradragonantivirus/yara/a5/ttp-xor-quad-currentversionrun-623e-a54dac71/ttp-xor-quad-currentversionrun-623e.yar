rule TTP_XOR_QUAD_CurrentVersionRun_623e {
  strings:
    $key_623e = { 31 51 [2] 15 5f [2] 3e 73 [2] 10 51 [2] 04 4a [2] 0b 50 [2] 15 4d [2] 17 4c [2] 0c 4a [2] 10 4d [2] 0c 62 }

  condition:
    any of them
}