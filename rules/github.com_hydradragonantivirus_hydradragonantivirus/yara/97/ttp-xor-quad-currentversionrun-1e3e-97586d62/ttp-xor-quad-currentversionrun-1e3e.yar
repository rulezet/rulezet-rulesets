rule TTP_XOR_QUAD_CurrentVersionRun_1e3e {
  strings:
    $key_1e3e = { 4d 51 [2] 69 5f [2] 42 73 [2] 6c 51 [2] 78 4a [2] 77 50 [2] 69 4d [2] 6b 4c [2] 70 4a [2] 6c 4d [2] 70 62 }

  condition:
    any of them
}