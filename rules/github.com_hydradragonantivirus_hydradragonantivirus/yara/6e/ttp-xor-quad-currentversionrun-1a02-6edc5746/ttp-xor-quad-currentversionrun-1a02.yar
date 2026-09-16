rule TTP_XOR_QUAD_CurrentVersionRun_1a02 {
  strings:
    $key_1a02 = { 49 6d [2] 6d 63 [2] 46 4f [2] 68 6d [2] 7c 76 [2] 73 6c [2] 6d 71 [2] 6f 70 [2] 74 76 [2] 68 71 [2] 74 5e }

  condition:
    any of them
}