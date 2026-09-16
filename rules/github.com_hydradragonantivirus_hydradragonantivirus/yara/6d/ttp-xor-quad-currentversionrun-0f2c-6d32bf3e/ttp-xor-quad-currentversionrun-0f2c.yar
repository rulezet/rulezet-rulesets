rule TTP_XOR_QUAD_CurrentVersionRun_0f2c {
  strings:
    $key_0f2c = { 5c 43 [2] 78 4d [2] 53 61 [2] 7d 43 [2] 69 58 [2] 66 42 [2] 78 5f [2] 7a 5e [2] 61 58 [2] 7d 5f [2] 61 70 }

  condition:
    any of them
}