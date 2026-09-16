rule TTP_XOR_QUAD_CurrentVersionRun_113b {
  strings:
    $key_113b = { 42 54 [2] 66 5a [2] 4d 76 [2] 63 54 [2] 77 4f [2] 78 55 [2] 66 48 [2] 64 49 [2] 7f 4f [2] 63 48 [2] 7f 67 }

  condition:
    any of them
}