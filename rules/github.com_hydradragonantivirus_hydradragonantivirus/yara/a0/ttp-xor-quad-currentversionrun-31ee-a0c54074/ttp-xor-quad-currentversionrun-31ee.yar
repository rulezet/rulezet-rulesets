rule TTP_XOR_QUAD_CurrentVersionRun_31ee {
  strings:
    $key_31ee = { 62 81 [2] 46 8f [2] 6d a3 [2] 43 81 [2] 57 9a [2] 58 80 [2] 46 9d [2] 44 9c [2] 5f 9a [2] 43 9d [2] 5f b2 }

  condition:
    any of them
}