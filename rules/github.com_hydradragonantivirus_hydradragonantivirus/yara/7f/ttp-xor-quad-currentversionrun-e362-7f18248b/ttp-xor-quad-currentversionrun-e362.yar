rule TTP_XOR_QUAD_CurrentVersionRun_e362 {
  strings:
    $key_e362 = { b0 0d [2] 94 03 [2] bf 2f [2] 91 0d [2] 85 16 [2] 8a 0c [2] 94 11 [2] 96 10 [2] 8d 16 [2] 91 11 [2] 8d 3e }

  condition:
    any of them
}