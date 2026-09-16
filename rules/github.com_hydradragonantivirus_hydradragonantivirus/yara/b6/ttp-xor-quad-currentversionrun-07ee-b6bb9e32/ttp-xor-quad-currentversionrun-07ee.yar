rule TTP_XOR_QUAD_CurrentVersionRun_07ee {
  strings:
    $key_07ee = { 54 81 [2] 70 8f [2] 5b a3 [2] 75 81 [2] 61 9a [2] 6e 80 [2] 70 9d [2] 72 9c [2] 69 9a [2] 75 9d [2] 69 b2 }

  condition:
    any of them
}