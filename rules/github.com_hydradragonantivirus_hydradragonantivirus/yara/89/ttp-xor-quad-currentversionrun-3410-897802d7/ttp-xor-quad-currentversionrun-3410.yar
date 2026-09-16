rule TTP_XOR_QUAD_CurrentVersionRun_3410 {
  strings:
    $key_3410 = { 67 7f [2] 43 71 [2] 68 5d [2] 46 7f [2] 52 64 [2] 5d 7e [2] 43 63 [2] 41 62 [2] 5a 64 [2] 46 63 [2] 5a 4c }

  condition:
    any of them
}