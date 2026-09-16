rule TTP_XOR_QUAD_CurrentVersionRun_212b {
  strings:
    $key_212b = { 72 44 [2] 56 4a [2] 7d 66 [2] 53 44 [2] 47 5f [2] 48 45 [2] 56 58 [2] 54 59 [2] 4f 5f [2] 53 58 [2] 4f 77 }

  condition:
    any of them
}