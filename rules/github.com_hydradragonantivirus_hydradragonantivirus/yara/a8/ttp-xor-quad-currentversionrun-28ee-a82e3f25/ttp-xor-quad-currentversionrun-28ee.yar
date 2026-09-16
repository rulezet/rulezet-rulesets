rule TTP_XOR_QUAD_CurrentVersionRun_28ee {
  strings:
    $key_28ee = { 7b 81 [2] 5f 8f [2] 74 a3 [2] 5a 81 [2] 4e 9a [2] 41 80 [2] 5f 9d [2] 5d 9c [2] 46 9a [2] 5a 9d [2] 46 b2 }

  condition:
    any of them
}