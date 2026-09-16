rule TTP_XOR_QUAD_CurrentVersionRun_e3ee {
  strings:
    $key_e3ee = { b0 81 [2] 94 8f [2] bf a3 [2] 91 81 [2] 85 9a [2] 8a 80 [2] 94 9d [2] 96 9c [2] 8d 9a [2] 91 9d [2] 8d b2 }

  condition:
    any of them
}