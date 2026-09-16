rule TTP_XOR_QUAD_CurrentVersionRun_243b {
  strings:
    $key_243b = { 77 54 [2] 53 5a [2] 78 76 [2] 56 54 [2] 42 4f [2] 4d 55 [2] 53 48 [2] 51 49 [2] 4a 4f [2] 56 48 [2] 4a 67 }

  condition:
    any of them
}