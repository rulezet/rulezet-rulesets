rule TTP_XOR_QUAD_CurrentVersionRun_7f11 {
  strings:
    $key_7f11 = { 2c 7e [2] 08 70 [2] 23 5c [2] 0d 7e [2] 19 65 [2] 16 7f [2] 08 62 [2] 0a 63 [2] 11 65 [2] 0d 62 [2] 11 4d }

  condition:
    any of them
}