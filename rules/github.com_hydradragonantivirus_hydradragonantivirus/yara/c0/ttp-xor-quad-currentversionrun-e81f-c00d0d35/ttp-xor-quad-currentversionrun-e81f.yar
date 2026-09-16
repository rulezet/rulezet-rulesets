rule TTP_XOR_QUAD_CurrentVersionRun_e81f {
  strings:
    $key_e81f = { bb 70 [2] 9f 7e [2] b4 52 [2] 9a 70 [2] 8e 6b [2] 81 71 [2] 9f 6c [2] 9d 6d [2] 86 6b [2] 9a 6c [2] 86 43 }

  condition:
    any of them
}