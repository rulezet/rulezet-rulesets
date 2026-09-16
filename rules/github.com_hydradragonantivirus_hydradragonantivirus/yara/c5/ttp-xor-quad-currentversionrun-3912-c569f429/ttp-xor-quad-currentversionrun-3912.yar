rule TTP_XOR_QUAD_CurrentVersionRun_3912 {
  strings:
    $key_3912 = { 6a 7d [2] 4e 73 [2] 65 5f [2] 4b 7d [2] 5f 66 [2] 50 7c [2] 4e 61 [2] 4c 60 [2] 57 66 [2] 4b 61 [2] 57 4e }

  condition:
    any of them
}