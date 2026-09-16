rule TTP_XOR_QUAD_CurrentVersionRun_663e {
  strings:
    $key_663e = { 35 51 [2] 11 5f [2] 3a 73 [2] 14 51 [2] 00 4a [2] 0f 50 [2] 11 4d [2] 13 4c [2] 08 4a [2] 14 4d [2] 08 62 }

  condition:
    any of them
}