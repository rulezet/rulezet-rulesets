rule TTP_XOR_QUAD_CurrentVersionRun_7e26 {
  strings:
    $key_7e26 = { 2d 49 [2] 09 47 [2] 22 6b [2] 0c 49 [2] 18 52 [2] 17 48 [2] 09 55 [2] 0b 54 [2] 10 52 [2] 0c 55 [2] 10 7a }

  condition:
    any of them
}