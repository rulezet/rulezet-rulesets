rule TTP_XOR_QUAD_CurrentVersionRun_2126 {
  strings:
    $key_2126 = { 72 49 [2] 56 47 [2] 7d 6b [2] 53 49 [2] 47 52 [2] 48 48 [2] 56 55 [2] 54 54 [2] 4f 52 [2] 53 55 [2] 4f 7a }

  condition:
    any of them
}