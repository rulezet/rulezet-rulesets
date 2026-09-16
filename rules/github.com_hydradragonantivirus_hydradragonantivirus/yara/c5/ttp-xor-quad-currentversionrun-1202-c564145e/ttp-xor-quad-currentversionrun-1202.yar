rule TTP_XOR_QUAD_CurrentVersionRun_1202 {
  strings:
    $key_1202 = { 41 6d [2] 65 63 [2] 4e 4f [2] 60 6d [2] 74 76 [2] 7b 6c [2] 65 71 [2] 67 70 [2] 7c 76 [2] 60 71 [2] 7c 5e }

  condition:
    any of them
}