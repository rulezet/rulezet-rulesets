rule TTP_XOR_QUAD_CurrentVersionRun_123e {
  strings:
    $key_123e = { 41 51 [2] 65 5f [2] 4e 73 [2] 60 51 [2] 74 4a [2] 7b 50 [2] 65 4d [2] 67 4c [2] 7c 4a [2] 60 4d [2] 7c 62 }

  condition:
    any of them
}