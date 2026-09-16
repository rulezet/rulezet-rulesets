rule TTP_XOR_QUAD_CurrentVersionRun_f4f2 {
  strings:
    $key_f4f2 = { a7 9d [2] 83 93 [2] a8 bf [2] 86 9d [2] 92 86 [2] 9d 9c [2] 83 81 [2] 81 80 [2] 9a 86 [2] 86 81 [2] 9a ae }

  condition:
    any of them
}