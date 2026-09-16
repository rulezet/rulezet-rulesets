rule TTP_XOR_QUAD_CurrentVersionRun_2502 {
  strings:
    $key_2502 = { 76 6d [2] 52 63 [2] 79 4f [2] 57 6d [2] 43 76 [2] 4c 6c [2] 52 71 [2] 50 70 [2] 4b 76 [2] 57 71 [2] 4b 5e }

  condition:
    any of them
}