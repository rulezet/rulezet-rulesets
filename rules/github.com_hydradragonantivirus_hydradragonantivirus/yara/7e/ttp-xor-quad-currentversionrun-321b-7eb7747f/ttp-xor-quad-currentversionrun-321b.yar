rule TTP_XOR_QUAD_CurrentVersionRun_321b {
  strings:
    $key_321b = { 61 74 [2] 45 7a [2] 6e 56 [2] 40 74 [2] 54 6f [2] 5b 75 [2] 45 68 [2] 47 69 [2] 5c 6f [2] 40 68 [2] 5c 47 }

  condition:
    any of them
}