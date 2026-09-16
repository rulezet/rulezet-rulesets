rule TTP_XOR_QUAD_CurrentVersionRun_2e02 {
  strings:
    $key_2e02 = { 7d 6d [2] 59 63 [2] 72 4f [2] 5c 6d [2] 48 76 [2] 47 6c [2] 59 71 [2] 5b 70 [2] 40 76 [2] 5c 71 [2] 40 5e }

  condition:
    any of them
}