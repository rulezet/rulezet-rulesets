rule TTP_XOR_QUAD_CurrentVersionRun_363e {
  strings:
    $key_363e = { 65 51 [2] 41 5f [2] 6a 73 [2] 44 51 [2] 50 4a [2] 5f 50 [2] 41 4d [2] 43 4c [2] 58 4a [2] 44 4d [2] 58 62 }

  condition:
    any of them
}