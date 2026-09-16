rule TTP_XOR_QUAD_CurrentVersionRun_7902 {
  strings:
    $key_7902 = { 2a 6d [2] 0e 63 [2] 25 4f [2] 0b 6d [2] 1f 76 [2] 10 6c [2] 0e 71 [2] 0c 70 [2] 17 76 [2] 0b 71 [2] 17 5e }

  condition:
    any of them
}