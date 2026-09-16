rule TTP_XOR_QUAD_CurrentVersionRun_1d62 {
  strings:
    $key_1d62 = { 4e 0d [2] 6a 03 [2] 41 2f [2] 6f 0d [2] 7b 16 [2] 74 0c [2] 6a 11 [2] 68 10 [2] 73 16 [2] 6f 11 [2] 73 3e }

  condition:
    any of them
}