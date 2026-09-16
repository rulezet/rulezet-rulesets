rule TTP_XOR_QUAD_CurrentVersionRun_0926 {
  strings:
    $key_0926 = { 5a 49 [2] 7e 47 [2] 55 6b [2] 7b 49 [2] 6f 52 [2] 60 48 [2] 7e 55 [2] 7c 54 [2] 67 52 [2] 7b 55 [2] 67 7a }

  condition:
    any of them
}