rule TTP_XOR_QUAD_CurrentVersionRun_6002 {
  strings:
    $key_6002 = { 33 6d [2] 17 63 [2] 3c 4f [2] 12 6d [2] 06 76 [2] 09 6c [2] 17 71 [2] 15 70 [2] 0e 76 [2] 12 71 [2] 0e 5e }

  condition:
    any of them
}