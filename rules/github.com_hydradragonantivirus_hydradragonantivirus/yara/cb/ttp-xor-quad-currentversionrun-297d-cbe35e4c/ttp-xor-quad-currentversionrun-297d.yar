rule TTP_XOR_QUAD_CurrentVersionRun_297d {
  strings:
    $key_297d = { 7a 12 [2] 5e 1c [2] 75 30 [2] 5b 12 [2] 4f 09 [2] 40 13 [2] 5e 0e [2] 5c 0f [2] 47 09 [2] 5b 0e [2] 47 21 }

  condition:
    any of them
}