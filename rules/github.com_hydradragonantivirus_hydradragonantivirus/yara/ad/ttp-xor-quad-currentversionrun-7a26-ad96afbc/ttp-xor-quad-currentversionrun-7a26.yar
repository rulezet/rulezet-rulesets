rule TTP_XOR_QUAD_CurrentVersionRun_7a26 {
  strings:
    $key_7a26 = { 29 49 [2] 0d 47 [2] 26 6b [2] 08 49 [2] 1c 52 [2] 13 48 [2] 0d 55 [2] 0f 54 [2] 14 52 [2] 08 55 [2] 14 7a }

  condition:
    any of them
}