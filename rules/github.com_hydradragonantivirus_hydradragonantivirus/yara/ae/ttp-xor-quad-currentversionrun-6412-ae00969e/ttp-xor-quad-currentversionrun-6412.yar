rule TTP_XOR_QUAD_CurrentVersionRun_6412 {
  strings:
    $key_6412 = { 37 7d [2] 13 73 [2] 38 5f [2] 16 7d [2] 02 66 [2] 0d 7c [2] 13 61 [2] 11 60 [2] 0a 66 [2] 16 61 [2] 0a 4e }

  condition:
    any of them
}