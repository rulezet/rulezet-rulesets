rule TTP_XOR_QUAD_CurrentVersionRun_0c12 {
  strings:
    $key_0c12 = { 5f 7d [2] 7b 73 [2] 50 5f [2] 7e 7d [2] 6a 66 [2] 65 7c [2] 7b 61 [2] 79 60 [2] 62 66 [2] 7e 61 [2] 62 4e }

  condition:
    any of them
}