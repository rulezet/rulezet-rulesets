rule TTP_XOR_QUAD_CurrentVersionRun_297c {
  strings:
    $key_297c = { 7a 13 [2] 5e 1d [2] 75 31 [2] 5b 13 [2] 4f 08 [2] 40 12 [2] 5e 0f [2] 5c 0e [2] 47 08 [2] 5b 0f [2] 47 20 }

  condition:
    any of them
}