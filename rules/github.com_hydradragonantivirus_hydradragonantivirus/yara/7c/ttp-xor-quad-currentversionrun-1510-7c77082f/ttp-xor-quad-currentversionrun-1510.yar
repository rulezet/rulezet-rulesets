rule TTP_XOR_QUAD_CurrentVersionRun_1510 {
  strings:
    $key_1510 = { 46 7f [2] 62 71 [2] 49 5d [2] 67 7f [2] 73 64 [2] 7c 7e [2] 62 63 [2] 60 62 [2] 7b 64 [2] 67 63 [2] 7b 4c }

  condition:
    any of them
}