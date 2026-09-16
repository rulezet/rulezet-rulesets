rule TTP_XOR_QUAD_CurrentVersionRun_364c {
  strings:
    $key_364c = { 65 23 [2] 41 2d [2] 6a 01 [2] 44 23 [2] 50 38 [2] 5f 22 [2] 41 3f [2] 43 3e [2] 58 38 [2] 44 3f [2] 58 10 }

  condition:
    any of them
}