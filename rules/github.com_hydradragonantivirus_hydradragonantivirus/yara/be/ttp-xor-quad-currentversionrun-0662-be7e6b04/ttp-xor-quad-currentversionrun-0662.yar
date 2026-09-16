rule TTP_XOR_QUAD_CurrentVersionRun_0662 {
  strings:
    $key_0662 = { 55 0d [2] 71 03 [2] 5a 2f [2] 74 0d [2] 60 16 [2] 6f 0c [2] 71 11 [2] 73 10 [2] 68 16 [2] 74 11 [2] 68 3e }

  condition:
    any of them
}