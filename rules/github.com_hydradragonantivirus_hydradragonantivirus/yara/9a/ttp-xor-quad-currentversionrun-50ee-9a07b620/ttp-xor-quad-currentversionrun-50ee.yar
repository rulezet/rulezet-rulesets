rule TTP_XOR_QUAD_CurrentVersionRun_50ee {
  strings:
    $key_50ee = { 03 81 [2] 27 8f [2] 0c a3 [2] 22 81 [2] 36 9a [2] 39 80 [2] 27 9d [2] 25 9c [2] 3e 9a [2] 22 9d [2] 3e b2 }

  condition:
    any of them
}