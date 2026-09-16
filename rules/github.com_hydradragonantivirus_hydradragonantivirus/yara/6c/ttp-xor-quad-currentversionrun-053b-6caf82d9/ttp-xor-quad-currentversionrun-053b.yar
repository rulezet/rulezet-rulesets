rule TTP_XOR_QUAD_CurrentVersionRun_053b {
  strings:
    $key_053b = { 56 54 [2] 72 5a [2] 59 76 [2] 77 54 [2] 63 4f [2] 6c 55 [2] 72 48 [2] 70 49 [2] 6b 4f [2] 77 48 [2] 6b 67 }

  condition:
    any of them
}