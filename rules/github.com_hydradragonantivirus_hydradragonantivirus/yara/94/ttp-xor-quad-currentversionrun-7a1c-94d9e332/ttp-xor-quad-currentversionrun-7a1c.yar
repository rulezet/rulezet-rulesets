rule TTP_XOR_QUAD_CurrentVersionRun_7a1c {
  strings:
    $key_7a1c = { 29 73 [2] 0d 7d [2] 26 51 [2] 08 73 [2] 1c 68 [2] 13 72 [2] 0d 6f [2] 0f 6e [2] 14 68 [2] 08 6f [2] 14 40 }

  condition:
    any of them
}