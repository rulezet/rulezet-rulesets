rule TTP_XOR_QUAD_CurrentVersionRun_2e26 {
  strings:
    $key_2e26 = { 7d 49 [2] 59 47 [2] 72 6b [2] 5c 49 [2] 48 52 [2] 47 48 [2] 59 55 [2] 5b 54 [2] 40 52 [2] 5c 55 [2] 40 7a }

  condition:
    any of them
}