rule TTP_XOR_QUAD_CurrentVersionRun_5112 {
  strings:
    $key_5112 = { 02 7d [2] 26 73 [2] 0d 5f [2] 23 7d [2] 37 66 [2] 38 7c [2] 26 61 [2] 24 60 [2] 3f 66 [2] 23 61 [2] 3f 4e }

  condition:
    any of them
}