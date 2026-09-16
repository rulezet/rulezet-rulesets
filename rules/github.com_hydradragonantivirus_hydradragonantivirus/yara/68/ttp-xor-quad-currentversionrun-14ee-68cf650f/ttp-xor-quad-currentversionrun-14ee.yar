rule TTP_XOR_QUAD_CurrentVersionRun_14ee {
  strings:
    $key_14ee = { 47 81 [2] 63 8f [2] 48 a3 [2] 66 81 [2] 72 9a [2] 7d 80 [2] 63 9d [2] 61 9c [2] 7a 9a [2] 66 9d [2] 7a b2 }

  condition:
    any of them
}