rule TTP_XOR_QUAD_CurrentVersionRun_6d02 {
  strings:
    $key_6d02 = { 3e 6d [2] 1a 63 [2] 31 4f [2] 1f 6d [2] 0b 76 [2] 04 6c [2] 1a 71 [2] 18 70 [2] 03 76 [2] 1f 71 [2] 03 5e }

  condition:
    any of them
}