rule TTP_XOR_QUAD_CurrentVersionRun_3cf2 {
  strings:
    $key_3cf2 = { 6f 9d [2] 4b 93 [2] 60 bf [2] 4e 9d [2] 5a 86 [2] 55 9c [2] 4b 81 [2] 49 80 [2] 52 86 [2] 4e 81 [2] 52 ae }

  condition:
    any of them
}