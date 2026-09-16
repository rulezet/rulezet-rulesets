rule TTP_XOR_QUAD_CurrentVersionRun_6039 {
  strings:
    $key_6039 = { 33 56 [2] 17 58 [2] 3c 74 [2] 12 56 [2] 06 4d [2] 09 57 [2] 17 4a [2] 15 4b [2] 0e 4d [2] 12 4a [2] 0e 65 }

  condition:
    any of them
}