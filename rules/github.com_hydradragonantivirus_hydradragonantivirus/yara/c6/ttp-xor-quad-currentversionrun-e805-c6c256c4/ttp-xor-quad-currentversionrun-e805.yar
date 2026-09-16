rule TTP_XOR_QUAD_CurrentVersionRun_e805 {
  strings:
    $key_e805 = { bb 6a [2] 9f 64 [2] b4 48 [2] 9a 6a [2] 8e 71 [2] 81 6b [2] 9f 76 [2] 9d 77 [2] 86 71 [2] 9a 76 [2] 86 59 }

  condition:
    any of them
}