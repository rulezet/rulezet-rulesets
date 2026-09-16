rule TTP_XOR_QUAD_CurrentVersionRun_063e {
  strings:
    $key_063e = { 55 51 [2] 71 5f [2] 5a 73 [2] 74 51 [2] 60 4a [2] 6f 50 [2] 71 4d [2] 73 4c [2] 68 4a [2] 74 4d [2] 68 62 }

  condition:
    any of them
}