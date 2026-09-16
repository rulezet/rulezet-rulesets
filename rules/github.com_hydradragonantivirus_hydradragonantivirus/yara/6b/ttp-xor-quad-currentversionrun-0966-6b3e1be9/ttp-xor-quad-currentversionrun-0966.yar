rule TTP_XOR_QUAD_CurrentVersionRun_0966 {
  strings:
    $key_0966 = { 5a 09 [2] 7e 07 [2] 55 2b [2] 7b 09 [2] 6f 12 [2] 60 08 [2] 7e 15 [2] 7c 14 [2] 67 12 [2] 7b 15 [2] 67 3a }

  condition:
    any of them
}