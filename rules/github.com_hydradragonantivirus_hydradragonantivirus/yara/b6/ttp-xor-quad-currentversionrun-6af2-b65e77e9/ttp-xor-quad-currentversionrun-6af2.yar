rule TTP_XOR_QUAD_CurrentVersionRun_6af2 {
  strings:
    $key_6af2 = { 39 9d [2] 1d 93 [2] 36 bf [2] 18 9d [2] 0c 86 [2] 03 9c [2] 1d 81 [2] 1f 80 [2] 04 86 [2] 18 81 [2] 04 ae }

  condition:
    any of them
}