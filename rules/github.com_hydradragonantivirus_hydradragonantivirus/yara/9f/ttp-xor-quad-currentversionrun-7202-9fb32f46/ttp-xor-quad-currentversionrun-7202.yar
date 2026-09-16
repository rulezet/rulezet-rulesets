rule TTP_XOR_QUAD_CurrentVersionRun_7202 {
  strings:
    $key_7202 = { 21 6d [2] 05 63 [2] 2e 4f [2] 00 6d [2] 14 76 [2] 1b 6c [2] 05 71 [2] 07 70 [2] 1c 76 [2] 00 71 [2] 1c 5e }

  condition:
    any of them
}