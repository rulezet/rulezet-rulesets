rule TTP_XOR_QUAD_CurrentVersionRun_2b3e {
  strings:
    $key_2b3e = { 78 51 [2] 5c 5f [2] 77 73 [2] 59 51 [2] 4d 4a [2] 42 50 [2] 5c 4d [2] 5e 4c [2] 45 4a [2] 59 4d [2] 45 62 }

  condition:
    any of them
}