rule TTP_XOR_QUAD_CurrentVersionRun_3811 {
  strings:
    $key_3811 = { 6b 7e [2] 4f 70 [2] 64 5c [2] 4a 7e [2] 5e 65 [2] 51 7f [2] 4f 62 [2] 4d 63 [2] 56 65 [2] 4a 62 [2] 56 4d }

  condition:
    any of them
}