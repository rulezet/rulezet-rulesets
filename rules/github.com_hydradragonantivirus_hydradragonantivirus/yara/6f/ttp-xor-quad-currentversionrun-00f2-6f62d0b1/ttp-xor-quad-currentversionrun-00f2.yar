rule TTP_XOR_QUAD_CurrentVersionRun_00f2 {
  strings:
    $key_00f2 = { 53 9d [2] 77 93 [2] 5c bf [2] 72 9d [2] 66 86 [2] 69 9c [2] 77 81 [2] 75 80 [2] 6e 86 [2] 72 81 [2] 6e ae }

  condition:
    any of them
}