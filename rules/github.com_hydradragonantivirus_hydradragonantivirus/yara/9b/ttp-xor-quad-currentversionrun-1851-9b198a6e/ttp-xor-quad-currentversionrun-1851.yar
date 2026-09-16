rule TTP_XOR_QUAD_CurrentVersionRun_1851 {
  strings:
    $key_1851 = { 4b 3e [2] 6f 30 [2] 44 1c [2] 6a 3e [2] 7e 25 [2] 71 3f [2] 6f 22 [2] 6d 23 [2] 76 25 [2] 6a 22 [2] 76 0d }

  condition:
    any of them
}