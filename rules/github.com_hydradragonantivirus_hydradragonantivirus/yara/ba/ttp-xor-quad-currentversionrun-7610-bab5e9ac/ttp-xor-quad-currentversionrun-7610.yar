rule TTP_XOR_QUAD_CurrentVersionRun_7610 {
  strings:
    $key_7610 = { 25 7f [2] 01 71 [2] 2a 5d [2] 04 7f [2] 10 64 [2] 1f 7e [2] 01 63 [2] 03 62 [2] 18 64 [2] 04 63 [2] 18 4c }

  condition:
    any of them
}