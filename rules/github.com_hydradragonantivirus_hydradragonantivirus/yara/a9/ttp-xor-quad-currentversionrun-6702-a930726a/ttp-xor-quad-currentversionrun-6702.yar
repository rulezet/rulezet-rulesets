rule TTP_XOR_QUAD_CurrentVersionRun_6702 {
  strings:
    $key_6702 = { 34 6d [2] 10 63 [2] 3b 4f [2] 15 6d [2] 01 76 [2] 0e 6c [2] 10 71 [2] 12 70 [2] 09 76 [2] 15 71 [2] 09 5e }

  condition:
    any of them
}