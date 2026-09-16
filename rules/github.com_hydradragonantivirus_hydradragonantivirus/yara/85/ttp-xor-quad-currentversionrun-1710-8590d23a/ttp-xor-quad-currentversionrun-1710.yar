rule TTP_XOR_QUAD_CurrentVersionRun_1710 {
  strings:
    $key_1710 = { 44 7f [2] 60 71 [2] 4b 5d [2] 65 7f [2] 71 64 [2] 7e 7e [2] 60 63 [2] 62 62 [2] 79 64 [2] 65 63 [2] 79 4c }

  condition:
    any of them
}