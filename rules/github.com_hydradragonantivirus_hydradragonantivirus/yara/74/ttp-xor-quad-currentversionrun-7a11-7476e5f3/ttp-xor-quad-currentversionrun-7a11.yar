rule TTP_XOR_QUAD_CurrentVersionRun_7a11 {
  strings:
    $key_7a11 = { 29 7e [2] 0d 70 [2] 26 5c [2] 08 7e [2] 1c 65 [2] 13 7f [2] 0d 62 [2] 0f 63 [2] 14 65 [2] 08 62 [2] 14 4d }

  condition:
    any of them
}