rule TTP_XOR_QUAD_CurrentVersionRun_5212 {
  strings:
    $key_5212 = { 01 7d [2] 25 73 [2] 0e 5f [2] 20 7d [2] 34 66 [2] 3b 7c [2] 25 61 [2] 27 60 [2] 3c 66 [2] 20 61 [2] 3c 4e }

  condition:
    any of them
}