rule TTP_XOR_QUAD_CurrentVersionRun_653d {
  strings:
    $key_653d = { 36 52 [2] 12 5c [2] 39 70 [2] 17 52 [2] 03 49 [2] 0c 53 [2] 12 4e [2] 10 4f [2] 0b 49 [2] 17 4e [2] 0b 61 }

  condition:
    any of them
}