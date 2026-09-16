rule TTP_XOR_QUAD_CurrentVersionRun_7a10 {
  strings:
    $key_7a10 = { 29 7f [2] 0d 71 [2] 26 5d [2] 08 7f [2] 1c 64 [2] 13 7e [2] 0d 63 [2] 0f 62 [2] 14 64 [2] 08 63 [2] 14 4c }

  condition:
    any of them
}