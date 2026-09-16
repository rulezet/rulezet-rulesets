rule TTP_XOR_QUAD_CurrentVersionRun_327c {
  strings:
    $key_327c = { 61 13 [2] 45 1d [2] 6e 31 [2] 40 13 [2] 54 08 [2] 5b 12 [2] 45 0f [2] 47 0e [2] 5c 08 [2] 40 0f [2] 5c 20 }

  condition:
    any of them
}