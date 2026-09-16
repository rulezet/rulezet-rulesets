rule TTP_XOR_QUAD_CurrentVersionRun_7a40 {
  strings:
    $key_7a40 = { 29 2f [2] 0d 21 [2] 26 0d [2] 08 2f [2] 1c 34 [2] 13 2e [2] 0d 33 [2] 0f 32 [2] 14 34 [2] 08 33 [2] 14 1c }

  condition:
    any of them
}