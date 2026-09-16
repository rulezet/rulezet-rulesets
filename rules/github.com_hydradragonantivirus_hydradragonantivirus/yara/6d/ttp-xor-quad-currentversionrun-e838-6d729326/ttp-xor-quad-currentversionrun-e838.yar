rule TTP_XOR_QUAD_CurrentVersionRun_e838 {
  strings:
    $key_e838 = { bb 57 [2] 9f 59 [2] b4 75 [2] 9a 57 [2] 8e 4c [2] 81 56 [2] 9f 4b [2] 9d 4a [2] 86 4c [2] 9a 4b [2] 86 64 }

  condition:
    any of them
}