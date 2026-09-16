rule TTP_XOR_QUAD_CurrentVersionRun_3c26 {
  strings:
    $key_3c26 = { 6f 49 [2] 4b 47 [2] 60 6b [2] 4e 49 [2] 5a 52 [2] 55 48 [2] 4b 55 [2] 49 54 [2] 52 52 [2] 4e 55 [2] 52 7a }

  condition:
    any of them
}