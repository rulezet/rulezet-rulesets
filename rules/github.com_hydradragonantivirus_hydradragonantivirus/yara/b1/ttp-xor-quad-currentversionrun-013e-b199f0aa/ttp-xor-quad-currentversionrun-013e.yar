rule TTP_XOR_QUAD_CurrentVersionRun_013e {
  strings:
    $key_013e = { 52 51 [2] 76 5f [2] 5d 73 [2] 73 51 [2] 67 4a [2] 68 50 [2] 76 4d [2] 74 4c [2] 6f 4a [2] 73 4d [2] 6f 62 }

  condition:
    any of them
}