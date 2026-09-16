rule TTP_XOR_QUAD_CurrentVersionRun_0c3e {
  strings:
    $key_0c3e = { 5f 51 [2] 7b 5f [2] 50 73 [2] 7e 51 [2] 6a 4a [2] 65 50 [2] 7b 4d [2] 79 4c [2] 62 4a [2] 7e 4d [2] 62 62 }

  condition:
    any of them
}