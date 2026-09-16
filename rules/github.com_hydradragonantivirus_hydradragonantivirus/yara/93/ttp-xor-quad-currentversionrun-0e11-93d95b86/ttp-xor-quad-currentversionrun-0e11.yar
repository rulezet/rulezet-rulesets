rule TTP_XOR_QUAD_CurrentVersionRun_0e11 {
  strings:
    $key_0e11 = { 5d 7e [2] 79 70 [2] 52 5c [2] 7c 7e [2] 68 65 [2] 67 7f [2] 79 62 [2] 7b 63 [2] 60 65 [2] 7c 62 [2] 60 4d }

  condition:
    any of them
}