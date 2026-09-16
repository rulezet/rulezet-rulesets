rule TTP_XOR_QUAD_CurrentVersionRun_6362 {
  strings:
    $key_6362 = { 30 0d [2] 14 03 [2] 3f 2f [2] 11 0d [2] 05 16 [2] 0a 0c [2] 14 11 [2] 16 10 [2] 0d 16 [2] 11 11 [2] 0d 3e }

  condition:
    any of them
}