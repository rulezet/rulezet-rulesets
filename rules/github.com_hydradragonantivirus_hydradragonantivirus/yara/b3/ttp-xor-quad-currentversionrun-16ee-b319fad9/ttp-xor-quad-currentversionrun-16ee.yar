rule TTP_XOR_QUAD_CurrentVersionRun_16ee {
  strings:
    $key_16ee = { 45 81 [2] 61 8f [2] 4a a3 [2] 64 81 [2] 70 9a [2] 7f 80 [2] 61 9d [2] 63 9c [2] 78 9a [2] 64 9d [2] 78 b2 }

  condition:
    any of them
}