rule TTP_XOR_QUAD_CurrentVersionRun_5612 {
  strings:
    $key_5612 = { 05 7d [2] 21 73 [2] 0a 5f [2] 24 7d [2] 30 66 [2] 3f 7c [2] 21 61 [2] 23 60 [2] 38 66 [2] 24 61 [2] 38 4e }

  condition:
    any of them
}