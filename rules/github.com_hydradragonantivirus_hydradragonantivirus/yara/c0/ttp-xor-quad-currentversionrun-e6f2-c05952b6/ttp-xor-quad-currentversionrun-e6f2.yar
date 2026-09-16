rule TTP_XOR_QUAD_CurrentVersionRun_e6f2 {
  strings:
    $key_e6f2 = { b5 9d [2] 91 93 [2] ba bf [2] 94 9d [2] 80 86 [2] 8f 9c [2] 91 81 [2] 93 80 [2] 88 86 [2] 94 81 [2] 88 ae }

  condition:
    any of them
}