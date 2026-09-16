rule TTP_XOR_QUAD_CurrentVersionRun_0812 {
  strings:
    $key_0812 = { 5b 7d [2] 7f 73 [2] 54 5f [2] 7a 7d [2] 6e 66 [2] 61 7c [2] 7f 61 [2] 7d 60 [2] 66 66 [2] 7a 61 [2] 66 4e }

  condition:
    any of them
}