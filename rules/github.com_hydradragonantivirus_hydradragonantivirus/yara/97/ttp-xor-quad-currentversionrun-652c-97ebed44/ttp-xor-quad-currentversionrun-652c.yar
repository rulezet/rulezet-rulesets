rule TTP_XOR_QUAD_CurrentVersionRun_652c {
  strings:
    $key_652c = { 36 43 [2] 12 4d [2] 39 61 [2] 17 43 [2] 03 58 [2] 0c 42 [2] 12 5f [2] 10 5e [2] 0b 58 [2] 17 5f [2] 0b 70 }

  condition:
    any of them
}