rule TTP_XOR_QUAD_CurrentVersionRun_3c12 {
  strings:
    $key_3c12 = { 6f 7d [2] 4b 73 [2] 60 5f [2] 4e 7d [2] 5a 66 [2] 55 7c [2] 4b 61 [2] 49 60 [2] 52 66 [2] 4e 61 [2] 52 4e }

  condition:
    any of them
}