rule TTP_XOR_QUAD_CurrentVersionRun_233b {
  strings:
    $key_233b = { 70 54 [2] 54 5a [2] 7f 76 [2] 51 54 [2] 45 4f [2] 4a 55 [2] 54 48 [2] 56 49 [2] 4d 4f [2] 51 48 [2] 4d 67 }

  condition:
    any of them
}