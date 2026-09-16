rule TTP_XOR_QUAD_CurrentVersionRun_23ef {
  strings:
    $key_23ef = { 70 80 [2] 54 8e [2] 7f a2 [2] 51 80 [2] 45 9b [2] 4a 81 [2] 54 9c [2] 56 9d [2] 4d 9b [2] 51 9c [2] 4d b3 }

  condition:
    any of them
}