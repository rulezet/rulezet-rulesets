rule TTP_XOR_QUAD_CurrentVersionRun_f226 {
  strings:
    $key_f226 = { a1 49 [2] 85 47 [2] ae 6b [2] 80 49 [2] 94 52 [2] 9b 48 [2] 85 55 [2] 87 54 [2] 9c 52 [2] 80 55 [2] 9c 7a }

  condition:
    any of them
}