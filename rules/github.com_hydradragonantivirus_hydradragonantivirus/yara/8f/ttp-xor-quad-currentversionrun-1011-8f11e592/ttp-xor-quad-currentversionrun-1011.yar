rule TTP_XOR_QUAD_CurrentVersionRun_1011 {
  strings:
    $key_1011 = { 43 7e [2] 67 70 [2] 4c 5c [2] 62 7e [2] 76 65 [2] 79 7f [2] 67 62 [2] 65 63 [2] 7e 65 [2] 62 62 [2] 7e 4d }

  condition:
    any of them
}