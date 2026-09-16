rule TTP_XOR_QUAD_CurrentVersionRun_e4f2 {
  strings:
    $key_e4f2 = { b7 9d [2] 93 93 [2] b8 bf [2] 96 9d [2] 82 86 [2] 8d 9c [2] 93 81 [2] 91 80 [2] 8a 86 [2] 96 81 [2] 8a ae }

  condition:
    any of them
}