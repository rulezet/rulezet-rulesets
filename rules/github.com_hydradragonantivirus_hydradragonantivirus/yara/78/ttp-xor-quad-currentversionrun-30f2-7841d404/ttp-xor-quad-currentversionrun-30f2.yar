rule TTP_XOR_QUAD_CurrentVersionRun_30f2 {
  strings:
    $key_30f2 = { 63 9d [2] 47 93 [2] 6c bf [2] 42 9d [2] 56 86 [2] 59 9c [2] 47 81 [2] 45 80 [2] 5e 86 [2] 42 81 [2] 5e ae }

  condition:
    any of them
}