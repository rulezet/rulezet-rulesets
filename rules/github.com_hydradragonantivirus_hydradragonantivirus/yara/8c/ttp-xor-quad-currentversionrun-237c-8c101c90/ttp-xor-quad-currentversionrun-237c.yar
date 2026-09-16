rule TTP_XOR_QUAD_CurrentVersionRun_237c {
  strings:
    $key_237c = { 70 13 [2] 54 1d [2] 7f 31 [2] 51 13 [2] 45 08 [2] 4a 12 [2] 54 0f [2] 56 0e [2] 4d 08 [2] 51 0f [2] 4d 20 }

  condition:
    any of them
}