rule TTP_XOR_QUAD_CurrentVersionRun_35ee {
  strings:
    $key_35ee = { 66 81 [2] 42 8f [2] 69 a3 [2] 47 81 [2] 53 9a [2] 5c 80 [2] 42 9d [2] 40 9c [2] 5b 9a [2] 47 9d [2] 5b b2 }

  condition:
    any of them
}