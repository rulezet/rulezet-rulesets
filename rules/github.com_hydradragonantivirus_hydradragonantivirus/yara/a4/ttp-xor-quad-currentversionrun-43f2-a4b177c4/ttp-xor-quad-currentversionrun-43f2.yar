rule TTP_XOR_QUAD_CurrentVersionRun_43f2 {
  strings:
    $key_43f2 = { 10 9d [2] 34 93 [2] 1f bf [2] 31 9d [2] 25 86 [2] 2a 9c [2] 34 81 [2] 36 80 [2] 2d 86 [2] 31 81 [2] 2d ae }

  condition:
    any of them
}