rule TTP_XOR_QUAD_CurrentVersionRun_0712 {
  strings:
    $key_0712 = { 54 7d [2] 70 73 [2] 5b 5f [2] 75 7d [2] 61 66 [2] 6e 7c [2] 70 61 [2] 72 60 [2] 69 66 [2] 75 61 [2] 69 4e }

  condition:
    any of them
}