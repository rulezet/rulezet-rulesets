rule TTP_XOR_QUAD_CurrentVersionRun_3c7c {
  strings:
    $key_3c7c = { 6f 13 [2] 4b 1d [2] 60 31 [2] 4e 13 [2] 5a 08 [2] 55 12 [2] 4b 0f [2] 49 0e [2] 52 08 [2] 4e 0f [2] 52 20 }

  condition:
    any of them
}