rule TTP_XOR_QUAD_CurrentVersionRun_7a5d {
  strings:
    $key_7a5d = { 29 32 [2] 0d 3c [2] 26 10 [2] 08 32 [2] 1c 29 [2] 13 33 [2] 0d 2e [2] 0f 2f [2] 14 29 [2] 08 2e [2] 14 01 }

  condition:
    any of them
}