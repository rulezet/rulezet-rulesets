rule TTP_XOR_QUAD_CurrentVersionRun_17ee {
  strings:
    $key_17ee = { 44 81 [2] 60 8f [2] 4b a3 [2] 65 81 [2] 71 9a [2] 7e 80 [2] 60 9d [2] 62 9c [2] 79 9a [2] 65 9d [2] 79 b2 }

  condition:
    any of them
}