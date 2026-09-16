rule TTP_XOR_QUAD_CurrentVersionRun_7a3b {
  strings:
    $key_7a3b = { 29 54 [2] 0d 5a [2] 26 76 [2] 08 54 [2] 1c 4f [2] 13 55 [2] 0d 48 [2] 0f 49 [2] 14 4f [2] 08 48 [2] 14 67 }

  condition:
    any of them
}