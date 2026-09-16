rule TTP_XOR_QUAD_CurrentVersionRun_e3f2 {
  strings:
    $key_e3f2 = { b0 9d [2] 94 93 [2] bf bf [2] 91 9d [2] 85 86 [2] 8a 9c [2] 94 81 [2] 96 80 [2] 8d 86 [2] 91 81 [2] 8d ae }

  condition:
    any of them
}