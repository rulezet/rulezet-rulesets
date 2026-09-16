rule TTP_XOR_QUAD_CurrentVersionRun_7600 {
  strings:
    $key_7600 = { 25 6f [2] 01 61 [2] 2a 4d [2] 04 6f [2] 10 74 [2] 1f 6e [2] 01 73 [2] 03 72 [2] 18 74 [2] 04 73 [2] 18 5c }

  condition:
    any of them
}