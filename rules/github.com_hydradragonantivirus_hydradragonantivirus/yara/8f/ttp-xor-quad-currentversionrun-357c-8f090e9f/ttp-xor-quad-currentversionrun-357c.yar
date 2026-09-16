rule TTP_XOR_QUAD_CurrentVersionRun_357c {
  strings:
    $key_357c = { 66 13 [2] 42 1d [2] 69 31 [2] 47 13 [2] 53 08 [2] 5c 12 [2] 42 0f [2] 40 0e [2] 5b 08 [2] 47 0f [2] 5b 20 }

  condition:
    any of them
}