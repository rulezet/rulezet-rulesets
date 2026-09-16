rule TTP_XOR_QUAD_CurrentVersionRun_260d {
  strings:
    $key_260d = { 75 62 [2] 51 6c [2] 7a 40 [2] 54 62 [2] 40 79 [2] 4f 63 [2] 51 7e [2] 53 7f [2] 48 79 [2] 54 7e [2] 48 51 }

  condition:
    any of them
}