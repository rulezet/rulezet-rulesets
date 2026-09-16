rule TTP_XOR_QUAD_CurrentVersionRun_383b {
  strings:
    $key_383b = { 6b 54 [2] 4f 5a [2] 64 76 [2] 4a 54 [2] 5e 4f [2] 51 55 [2] 4f 48 [2] 4d 49 [2] 56 4f [2] 4a 48 [2] 56 67 }

  condition:
    any of them
}