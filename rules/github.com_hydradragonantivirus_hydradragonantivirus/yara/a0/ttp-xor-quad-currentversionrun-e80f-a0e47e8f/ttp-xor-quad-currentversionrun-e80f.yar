rule TTP_XOR_QUAD_CurrentVersionRun_e80f {
  strings:
    $key_e80f = { bb 60 [2] 9f 6e [2] b4 42 [2] 9a 60 [2] 8e 7b [2] 81 61 [2] 9f 7c [2] 9d 7d [2] 86 7b [2] 9a 7c [2] 86 53 }

  condition:
    any of them
}