rule TTP_XOR_QUAD_CurrentVersionRun_352b {
  strings:
    $key_352b = { 66 44 [2] 42 4a [2] 69 66 [2] 47 44 [2] 53 5f [2] 5c 45 [2] 42 58 [2] 40 59 [2] 5b 5f [2] 47 58 [2] 5b 77 }

  condition:
    any of them
}