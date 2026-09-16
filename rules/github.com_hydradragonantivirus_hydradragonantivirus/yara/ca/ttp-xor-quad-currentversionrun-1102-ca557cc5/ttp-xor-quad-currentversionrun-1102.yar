rule TTP_XOR_QUAD_CurrentVersionRun_1102 {
  strings:
    $key_1102 = { 42 6d [2] 66 63 [2] 4d 4f [2] 63 6d [2] 77 76 [2] 78 6c [2] 66 71 [2] 64 70 [2] 7f 76 [2] 63 71 [2] 7f 5e }

  condition:
    any of them
}