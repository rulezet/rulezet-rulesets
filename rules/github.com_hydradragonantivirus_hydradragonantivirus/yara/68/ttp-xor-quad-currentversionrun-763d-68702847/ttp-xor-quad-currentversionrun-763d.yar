rule TTP_XOR_QUAD_CurrentVersionRun_763d {
  strings:
    $key_763d = { 25 52 [2] 01 5c [2] 2a 70 [2] 04 52 [2] 10 49 [2] 1f 53 [2] 01 4e [2] 03 4f [2] 18 49 [2] 04 4e [2] 18 61 }

  condition:
    any of them
}