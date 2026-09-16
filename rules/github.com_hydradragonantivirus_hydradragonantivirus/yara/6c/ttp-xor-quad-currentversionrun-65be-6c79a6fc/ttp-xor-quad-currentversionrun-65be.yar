rule TTP_XOR_QUAD_CurrentVersionRun_65be {
  strings:
    $key_65be = { 36 d1 [2] 12 df [2] 39 f3 [2] 17 d1 [2] 03 ca [2] 0c d0 [2] 12 cd [2] 10 cc [2] 0b ca [2] 17 cd [2] 0b e2 }

  condition:
    any of them
}