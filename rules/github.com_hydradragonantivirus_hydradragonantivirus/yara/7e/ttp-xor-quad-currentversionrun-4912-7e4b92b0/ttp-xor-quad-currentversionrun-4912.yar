rule TTP_XOR_QUAD_CurrentVersionRun_4912 {
  strings:
    $key_4912 = { 1a 7d [2] 3e 73 [2] 15 5f [2] 3b 7d [2] 2f 66 [2] 20 7c [2] 3e 61 [2] 3c 60 [2] 27 66 [2] 3b 61 [2] 27 4e }

  condition:
    any of them
}