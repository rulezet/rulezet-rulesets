rule TTP_XOR_QUAD_CurrentVersionRun_6011 {
  strings:
    $key_6011 = { 33 7e [2] 17 70 [2] 3c 5c [2] 12 7e [2] 06 65 [2] 09 7f [2] 17 62 [2] 15 63 [2] 0e 65 [2] 12 62 [2] 0e 4d }

  condition:
    any of them
}