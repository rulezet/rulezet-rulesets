rule TTP_XOR_QUAD_CurrentVersionRun_45be {
  strings:
    $key_45be = { 16 d1 [2] 32 df [2] 19 f3 [2] 37 d1 [2] 23 ca [2] 2c d0 [2] 32 cd [2] 30 cc [2] 2b ca [2] 37 cd [2] 2b e2 }

  condition:
    any of them
}