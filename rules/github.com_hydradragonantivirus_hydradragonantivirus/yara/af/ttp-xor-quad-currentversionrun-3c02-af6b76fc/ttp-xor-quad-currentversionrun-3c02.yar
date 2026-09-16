rule TTP_XOR_QUAD_CurrentVersionRun_3c02 {
  strings:
    $key_3c02 = { 6f 6d [2] 4b 63 [2] 60 4f [2] 4e 6d [2] 5a 76 [2] 55 6c [2] 4b 71 [2] 49 70 [2] 52 76 [2] 4e 71 [2] 52 5e }

  condition:
    any of them
}