rule TTP_XOR_QUAD_CurrentVersionRun_6226 {
  strings:
    $key_6226 = { 31 49 [2] 15 47 [2] 3e 6b [2] 10 49 [2] 04 52 [2] 0b 48 [2] 15 55 [2] 17 54 [2] 0c 52 [2] 10 55 [2] 0c 7a }

  condition:
    any of them
}