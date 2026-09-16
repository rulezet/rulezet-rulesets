rule TTP_XOR_QUAD_CurrentVersionRun_6312 {
  strings:
    $key_6312 = { 30 7d [2] 14 73 [2] 3f 5f [2] 11 7d [2] 05 66 [2] 0a 7c [2] 14 61 [2] 16 60 [2] 0d 66 [2] 11 61 [2] 0d 4e }

  condition:
    any of them
}