rule TTP_XOR_QUAD_CurrentVersionRun_7e3b {
  strings:
    $key_7e3b = { 2d 54 [2] 09 5a [2] 22 76 [2] 0c 54 [2] 18 4f [2] 17 55 [2] 09 48 [2] 0b 49 [2] 10 4f [2] 0c 48 [2] 10 67 }

  condition:
    any of them
}