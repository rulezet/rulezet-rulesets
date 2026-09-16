rule TTP_XOR_QUAD_CurrentVersionRun_7a0d {
  strings:
    $key_7a0d = { 29 62 [2] 0d 6c [2] 26 40 [2] 08 62 [2] 1c 79 [2] 13 63 [2] 0d 7e [2] 0f 7f [2] 14 79 [2] 08 7e [2] 14 51 }

  condition:
    any of them
}