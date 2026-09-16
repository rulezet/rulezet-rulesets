rule TTP_XOR_QUAD_CurrentVersionRun_6411 {
  strings:
    $key_6411 = { 37 7e [2] 13 70 [2] 38 5c [2] 16 7e [2] 02 65 [2] 0d 7f [2] 13 62 [2] 11 63 [2] 0a 65 [2] 16 62 [2] 0a 4d }

  condition:
    any of them
}