rule TTP_XOR_QUAD_CurrentVersionRun_3df2 {
  strings:
    $key_3df2 = { 6e 9d [2] 4a 93 [2] 61 bf [2] 4f 9d [2] 5b 86 [2] 54 9c [2] 4a 81 [2] 48 80 [2] 53 86 [2] 4f 81 [2] 53 ae }

  condition:
    any of them
}