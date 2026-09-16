rule TTP_XOR_QUAD_CurrentVersionRun_e8fe {
  strings:
    $key_e8fe = { bb 91 [2] 9f 9f [2] b4 b3 [2] 9a 91 [2] 8e 8a [2] 81 90 [2] 9f 8d [2] 9d 8c [2] 86 8a [2] 9a 8d [2] 86 a2 }

  condition:
    any of them
}