rule TTP_XOR_QUAD_CurrentVersionRun_7f32 {
  strings:
    $key_7f32 = { 2c 5d [2] 08 53 [2] 23 7f [2] 0d 5d [2] 19 46 [2] 16 5c [2] 08 41 [2] 0a 40 [2] 11 46 [2] 0d 41 [2] 11 6e }

  condition:
    any of them
}