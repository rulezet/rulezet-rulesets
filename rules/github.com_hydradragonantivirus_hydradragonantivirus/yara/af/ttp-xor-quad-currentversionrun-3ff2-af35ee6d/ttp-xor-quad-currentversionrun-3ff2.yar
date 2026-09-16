rule TTP_XOR_QUAD_CurrentVersionRun_3ff2 {
  strings:
    $key_3ff2 = { 6c 9d [2] 48 93 [2] 63 bf [2] 4d 9d [2] 59 86 [2] 56 9c [2] 48 81 [2] 4a 80 [2] 51 86 [2] 4d 81 [2] 51 ae }

  condition:
    any of them
}