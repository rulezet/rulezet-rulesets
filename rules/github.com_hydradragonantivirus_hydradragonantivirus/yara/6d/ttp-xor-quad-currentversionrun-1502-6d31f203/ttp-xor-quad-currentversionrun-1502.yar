rule TTP_XOR_QUAD_CurrentVersionRun_1502 {
  strings:
    $key_1502 = { 46 6d [2] 62 63 [2] 49 4f [2] 67 6d [2] 73 76 [2] 7c 6c [2] 62 71 [2] 60 70 [2] 7b 76 [2] 67 71 [2] 7b 5e }

  condition:
    any of them
}