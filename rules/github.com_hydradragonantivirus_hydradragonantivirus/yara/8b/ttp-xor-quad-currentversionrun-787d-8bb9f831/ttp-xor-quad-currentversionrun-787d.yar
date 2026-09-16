rule TTP_XOR_QUAD_CurrentVersionRun_787d {
  strings:
    $key_787d = { 2b 12 [2] 0f 1c [2] 24 30 [2] 0a 12 [2] 1e 09 [2] 11 13 [2] 0f 0e [2] 0d 0f [2] 16 09 [2] 0a 0e [2] 16 21 }

  condition:
    any of them
}