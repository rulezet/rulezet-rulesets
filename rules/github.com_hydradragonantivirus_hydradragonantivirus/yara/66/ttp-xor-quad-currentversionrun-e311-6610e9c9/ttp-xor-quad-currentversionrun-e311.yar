rule TTP_XOR_QUAD_CurrentVersionRun_e311 {
  strings:
    $key_e311 = { b0 7e [2] 94 70 [2] bf 5c [2] 91 7e [2] 85 65 [2] 8a 7f [2] 94 62 [2] 96 63 [2] 8d 65 [2] 91 62 [2] 8d 4d }

  condition:
    any of them
}