rule TTP_XOR_QUAD_CurrentVersionRun_e809 {
  strings:
    $key_e809 = { bb 66 [2] 9f 68 [2] b4 44 [2] 9a 66 [2] 8e 7d [2] 81 67 [2] 9f 7a [2] 9d 7b [2] 86 7d [2] 9a 7a [2] 86 55 }

  condition:
    any of them
}