rule TTP_XOR_QUAD_CurrentVersionRun_5502 {
  strings:
    $key_5502 = { 06 6d [2] 22 63 [2] 09 4f [2] 27 6d [2] 33 76 [2] 3c 6c [2] 22 71 [2] 20 70 [2] 3b 76 [2] 27 71 [2] 3b 5e }

  condition:
    any of them
}