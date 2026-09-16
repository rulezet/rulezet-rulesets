rule TTP_XOR_QUAD_CurrentVersionRun_7722 {
  strings:
    $key_7722 = { 24 4d [2] 00 43 [2] 2b 6f [2] 05 4d [2] 11 56 [2] 1e 4c [2] 00 51 [2] 02 50 [2] 19 56 [2] 05 51 [2] 19 7e }

  condition:
    any of them
}