rule TTP_XOR_QUAD_CurrentVersionRun_2bf2 {
  strings:
    $key_2bf2 = { 78 9d [2] 5c 93 [2] 77 bf [2] 59 9d [2] 4d 86 [2] 42 9c [2] 5c 81 [2] 5e 80 [2] 45 86 [2] 59 81 [2] 45 ae }

  condition:
    any of them
}