rule TTP_XOR_QUAD_CurrentVersionRun_0b3e {
  strings:
    $key_0b3e = { 58 51 [2] 7c 5f [2] 57 73 [2] 79 51 [2] 6d 4a [2] 62 50 [2] 7c 4d [2] 7e 4c [2] 65 4a [2] 79 4d [2] 65 62 }

  condition:
    any of them
}