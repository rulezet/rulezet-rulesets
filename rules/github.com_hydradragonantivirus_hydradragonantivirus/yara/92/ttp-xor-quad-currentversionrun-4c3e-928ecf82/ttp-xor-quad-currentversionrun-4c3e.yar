rule TTP_XOR_QUAD_CurrentVersionRun_4c3e {
  strings:
    $key_4c3e = { 1f 51 [2] 3b 5f [2] 10 73 [2] 3e 51 [2] 2a 4a [2] 25 50 [2] 3b 4d [2] 39 4c [2] 22 4a [2] 3e 4d [2] 22 62 }

  condition:
    any of them
}