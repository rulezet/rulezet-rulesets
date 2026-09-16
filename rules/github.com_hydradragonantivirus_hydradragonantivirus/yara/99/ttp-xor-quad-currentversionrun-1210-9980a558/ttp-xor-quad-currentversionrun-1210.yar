rule TTP_XOR_QUAD_CurrentVersionRun_1210 {
  strings:
    $key_1210 = { 41 7f [2] 65 71 [2] 4e 5d [2] 60 7f [2] 74 64 [2] 7b 7e [2] 65 63 [2] 67 62 [2] 7c 64 [2] 60 63 [2] 7c 4c }

  condition:
    any of them
}