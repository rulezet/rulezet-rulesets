rule TTP_XOR_QUAD_CurrentVersionRun_f6f2 {
  strings:
    $key_f6f2 = { a5 9d [2] 81 93 [2] aa bf [2] 84 9d [2] 90 86 [2] 9f 9c [2] 81 81 [2] 83 80 [2] 98 86 [2] 84 81 [2] 98 ae }

  condition:
    any of them
}