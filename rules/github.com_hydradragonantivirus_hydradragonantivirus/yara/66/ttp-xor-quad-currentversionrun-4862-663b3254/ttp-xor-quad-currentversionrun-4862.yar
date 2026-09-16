rule TTP_XOR_QUAD_CurrentVersionRun_4862 {
  strings:
    $key_4862 = { 1b 0d [2] 3f 03 [2] 14 2f [2] 3a 0d [2] 2e 16 [2] 21 0c [2] 3f 11 [2] 3d 10 [2] 26 16 [2] 3a 11 [2] 26 3e }

  condition:
    any of them
}