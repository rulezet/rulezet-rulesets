rule TTP_XOR_QUAD_CurrentVersionRun_015a {
  strings:
    $key_015a = { 52 35 [2] 76 3b [2] 5d 17 [2] 73 35 [2] 67 2e [2] 68 34 [2] 76 29 [2] 74 28 [2] 6f 2e [2] 73 29 [2] 6f 06 }

  condition:
    any of them
}