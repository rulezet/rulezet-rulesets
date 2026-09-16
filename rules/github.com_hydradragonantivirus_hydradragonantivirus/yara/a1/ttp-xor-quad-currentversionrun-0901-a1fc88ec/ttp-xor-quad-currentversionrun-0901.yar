rule TTP_XOR_QUAD_CurrentVersionRun_0901 {
  strings:
    $key_0901 = { 5a 6e [2] 7e 60 [2] 55 4c [2] 7b 6e [2] 6f 75 [2] 60 6f [2] 7e 72 [2] 7c 73 [2] 67 75 [2] 7b 72 [2] 67 5d }

  condition:
    any of them
}