rule TTP_XOR_QUAD_CurrentVersionRun_30ee {
  strings:
    $key_30ee = { 63 81 [2] 47 8f [2] 6c a3 [2] 42 81 [2] 56 9a [2] 59 80 [2] 47 9d [2] 45 9c [2] 5e 9a [2] 42 9d [2] 5e b2 }

  condition:
    any of them
}