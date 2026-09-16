rule TTP_XOR_QUAD_CurrentVersionRun_633d {
  strings:
    $key_633d = { 30 52 [2] 14 5c [2] 3f 70 [2] 11 52 [2] 05 49 [2] 0a 53 [2] 14 4e [2] 16 4f [2] 0d 49 [2] 11 4e [2] 0d 61 }

  condition:
    any of them
}