rule TTP_XOR_QUAD_CurrentVersionRun_2c3d {
  strings:
    $key_2c3d = { 7f 52 [2] 5b 5c [2] 70 70 [2] 5e 52 [2] 4a 49 [2] 45 53 [2] 5b 4e [2] 59 4f [2] 42 49 [2] 5e 4e [2] 42 61 }

  condition:
    any of them
}