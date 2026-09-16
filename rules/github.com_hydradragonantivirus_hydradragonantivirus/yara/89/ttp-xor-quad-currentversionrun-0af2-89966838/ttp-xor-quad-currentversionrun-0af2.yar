rule TTP_XOR_QUAD_CurrentVersionRun_0af2 {
  strings:
    $key_0af2 = { 59 9d [2] 7d 93 [2] 56 bf [2] 78 9d [2] 6c 86 [2] 63 9c [2] 7d 81 [2] 7f 80 [2] 64 86 [2] 78 81 [2] 64 ae }

  condition:
    any of them
}