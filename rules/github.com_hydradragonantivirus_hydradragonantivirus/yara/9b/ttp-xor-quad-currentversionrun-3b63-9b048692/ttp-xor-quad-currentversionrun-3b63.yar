rule TTP_XOR_QUAD_CurrentVersionRun_3b63 {
  strings:
    $key_3b63 = { 68 0c [2] 4c 02 [2] 67 2e [2] 49 0c [2] 5d 17 [2] 52 0d [2] 4c 10 [2] 4e 11 [2] 55 17 [2] 49 10 [2] 55 3f }

  condition:
    any of them
}