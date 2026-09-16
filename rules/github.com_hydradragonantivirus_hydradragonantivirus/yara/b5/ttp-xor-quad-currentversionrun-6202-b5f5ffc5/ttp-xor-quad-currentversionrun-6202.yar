rule TTP_XOR_QUAD_CurrentVersionRun_6202 {
  strings:
    $key_6202 = { 31 6d [2] 15 63 [2] 3e 4f [2] 10 6d [2] 04 76 [2] 0b 6c [2] 15 71 [2] 17 70 [2] 0c 76 [2] 10 71 [2] 0c 5e }

  condition:
    any of them
}