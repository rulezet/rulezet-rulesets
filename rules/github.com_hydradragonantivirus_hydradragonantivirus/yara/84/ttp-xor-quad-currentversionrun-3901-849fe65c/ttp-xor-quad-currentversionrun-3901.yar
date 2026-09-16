rule TTP_XOR_QUAD_CurrentVersionRun_3901 {
  strings:
    $key_3901 = { 6a 6e [2] 4e 60 [2] 65 4c [2] 4b 6e [2] 5f 75 [2] 50 6f [2] 4e 72 [2] 4c 73 [2] 57 75 [2] 4b 72 [2] 57 5d }

  condition:
    any of them
}