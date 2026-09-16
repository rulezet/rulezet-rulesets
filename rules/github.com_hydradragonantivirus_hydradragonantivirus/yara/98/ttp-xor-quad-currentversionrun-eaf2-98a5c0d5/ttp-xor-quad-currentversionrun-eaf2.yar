rule TTP_XOR_QUAD_CurrentVersionRun_eaf2 {
  strings:
    $key_eaf2 = { b9 9d [2] 9d 93 [2] b6 bf [2] 98 9d [2] 8c 86 [2] 83 9c [2] 9d 81 [2] 9f 80 [2] 84 86 [2] 98 81 [2] 84 ae }

  condition:
    any of them
}