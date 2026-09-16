rule TTP_XOR_QUAD_CurrentVersionRun_08ee {
  strings:
    $key_08ee = { 5b 81 [2] 7f 8f [2] 54 a3 [2] 7a 81 [2] 6e 9a [2] 61 80 [2] 7f 9d [2] 7d 9c [2] 66 9a [2] 7a 9d [2] 66 b2 }

  condition:
    any of them
}