rule TTP_XOR_QUAD_CurrentVersionRun_4b3b {
  strings:
    $key_4b3b = { 18 54 [2] 3c 5a [2] 17 76 [2] 39 54 [2] 2d 4f [2] 22 55 [2] 3c 48 [2] 3e 49 [2] 25 4f [2] 39 48 [2] 25 67 }

  condition:
    any of them
}