rule TTP_XOR_QUAD_CurrentVersionRun_38f2 {
  strings:
    $key_38f2 = { 6b 9d [2] 4f 93 [2] 64 bf [2] 4a 9d [2] 5e 86 [2] 51 9c [2] 4f 81 [2] 4d 80 [2] 56 86 [2] 4a 81 [2] 56 ae }

  condition:
    any of them
}