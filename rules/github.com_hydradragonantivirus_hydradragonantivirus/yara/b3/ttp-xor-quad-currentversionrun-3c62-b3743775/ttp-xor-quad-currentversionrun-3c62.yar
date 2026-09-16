rule TTP_XOR_QUAD_CurrentVersionRun_3c62 {
  strings:
    $key_3c62 = { 6f 0d [2] 4b 03 [2] 60 2f [2] 4e 0d [2] 5a 16 [2] 55 0c [2] 4b 11 [2] 49 10 [2] 52 16 [2] 4e 11 [2] 52 3e }

  condition:
    any of them
}