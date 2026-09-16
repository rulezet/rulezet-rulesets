rule TTP_XOR_QUAD_CurrentVersionRun_e3e9 {
  strings:
    $key_e3e9 = { b0 86 [2] 94 88 [2] bf a4 [2] 91 86 [2] 85 9d [2] 8a 87 [2] 94 9a [2] 96 9b [2] 8d 9d [2] 91 9a [2] 8d b5 }

  condition:
    any of them
}