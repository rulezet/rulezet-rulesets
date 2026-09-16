rule TTP_XOR_QUAD_CurrentVersionRun_303b {
  strings:
    $key_303b = { 63 54 [2] 47 5a [2] 6c 76 [2] 42 54 [2] 56 4f [2] 59 55 [2] 47 48 [2] 45 49 [2] 5e 4f [2] 42 48 [2] 5e 67 }

  condition:
    any of them
}