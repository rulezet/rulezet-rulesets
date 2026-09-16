rule TTP_XOR_QUAD_CurrentVersionRun_24ee {
  strings:
    $key_24ee = { 77 81 [2] 53 8f [2] 78 a3 [2] 56 81 [2] 42 9a [2] 4d 80 [2] 53 9d [2] 51 9c [2] 4a 9a [2] 56 9d [2] 4a b2 }

  condition:
    any of them
}