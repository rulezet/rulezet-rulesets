rule TTP_XOR_QUAD_CurrentVersionRun_7502 {
  strings:
    $key_7502 = { 26 6d [2] 02 63 [2] 29 4f [2] 07 6d [2] 13 76 [2] 1c 6c [2] 02 71 [2] 00 70 [2] 1b 76 [2] 07 71 [2] 1b 5e }

  condition:
    any of them
}