rule TTP_XOR_QUAD_CurrentVersionRun_6722 {
  strings:
    $key_6722 = { 34 4d [2] 10 43 [2] 3b 6f [2] 15 4d [2] 01 56 [2] 0e 4c [2] 10 51 [2] 12 50 [2] 09 56 [2] 15 51 [2] 09 7e }

  condition:
    any of them
}