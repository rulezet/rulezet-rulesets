rule TTP_XOR_QUAD_CurrentVersionRun_59f2 {
  strings:
    $key_59f2 = { 0a 9d [2] 2e 93 [2] 05 bf [2] 2b 9d [2] 3f 86 [2] 30 9c [2] 2e 81 [2] 2c 80 [2] 37 86 [2] 2b 81 [2] 37 ae }

  condition:
    any of them
}