rule TTP_XOR_QUAD_CurrentVersionRun_69ee {
  strings:
    $key_69ee = { 3a 81 [2] 1e 8f [2] 35 a3 [2] 1b 81 [2] 0f 9a [2] 00 80 [2] 1e 9d [2] 1c 9c [2] 07 9a [2] 1b 9d [2] 07 b2 }

  condition:
    any of them
}