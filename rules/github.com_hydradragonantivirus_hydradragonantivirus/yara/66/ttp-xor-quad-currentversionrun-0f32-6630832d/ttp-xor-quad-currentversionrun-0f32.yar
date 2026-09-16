rule TTP_XOR_QUAD_CurrentVersionRun_0f32 {
  strings:
    $key_0f32 = { 5c 5d [2] 78 53 [2] 53 7f [2] 7d 5d [2] 69 46 [2] 66 5c [2] 78 41 [2] 7a 40 [2] 61 46 [2] 7d 41 [2] 61 6e }

  condition:
    any of them
}