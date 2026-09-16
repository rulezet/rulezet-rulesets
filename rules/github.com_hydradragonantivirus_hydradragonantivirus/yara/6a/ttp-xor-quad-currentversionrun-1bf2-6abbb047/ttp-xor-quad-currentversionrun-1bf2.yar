rule TTP_XOR_QUAD_CurrentVersionRun_1bf2 {
  strings:
    $key_1bf2 = { 48 9d [2] 6c 93 [2] 47 bf [2] 69 9d [2] 7d 86 [2] 72 9c [2] 6c 81 [2] 6e 80 [2] 75 86 [2] 69 81 [2] 75 ae }

  condition:
    any of them
}