rule TTP_XOR_QUAD_CurrentVersionRun_6c26 {
  strings:
    $key_6c26 = { 3f 49 [2] 1b 47 [2] 30 6b [2] 1e 49 [2] 0a 52 [2] 05 48 [2] 1b 55 [2] 19 54 [2] 02 52 [2] 1e 55 [2] 02 7a }

  condition:
    any of them
}