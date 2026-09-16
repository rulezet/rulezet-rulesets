rule TTP_XOR_QUAD_CurrentVersionRun_29f3 {
  strings:
    $key_29f3 = { 7a 9c [2] 5e 92 [2] 75 be [2] 5b 9c [2] 4f 87 [2] 40 9d [2] 5e 80 [2] 5c 81 [2] 47 87 [2] 5b 80 [2] 47 af }

  condition:
    any of them
}