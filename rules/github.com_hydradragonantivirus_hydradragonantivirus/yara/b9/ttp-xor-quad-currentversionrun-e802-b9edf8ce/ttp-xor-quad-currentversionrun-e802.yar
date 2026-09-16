rule TTP_XOR_QUAD_CurrentVersionRun_e802 {
  strings:
    $key_e802 = { bb 6d [2] 9f 63 [2] b4 4f [2] 9a 6d [2] 8e 76 [2] 81 6c [2] 9f 71 [2] 9d 70 [2] 86 76 [2] 9a 71 [2] 86 5e }

  condition:
    any of them
}