rule TTP_XOR_QUAD_CurrentVersionRun_91f2 {
  strings:
    $key_91f2 = { c2 9d [2] e6 93 [2] cd bf [2] e3 9d [2] f7 86 [2] f8 9c [2] e6 81 [2] e4 80 [2] ff 86 [2] e3 81 [2] ff ae }

  condition:
    any of them
}