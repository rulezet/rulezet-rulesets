rule TTP_XOR_QUAD_CurrentVersionRun_5411 {
  strings:
    $key_5411 = { 07 7e [2] 23 70 [2] 08 5c [2] 26 7e [2] 32 65 [2] 3d 7f [2] 23 62 [2] 21 63 [2] 3a 65 [2] 26 62 [2] 3a 4d }

  condition:
    any of them
}