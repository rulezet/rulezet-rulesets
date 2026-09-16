rule TTP_XOR_QUAD_CurrentVersionRun_503b {
  strings:
    $key_503b = { 03 54 [2] 27 5a [2] 0c 76 [2] 22 54 [2] 36 4f [2] 39 55 [2] 27 48 [2] 25 49 [2] 3e 4f [2] 22 48 [2] 3e 67 }

  condition:
    any of them
}