rule TTP_XOR_QUAD_CurrentVersionRun_25be {
  strings:
    $key_25be = { 76 d1 [2] 52 df [2] 79 f3 [2] 57 d1 [2] 43 ca [2] 4c d0 [2] 52 cd [2] 50 cc [2] 4b ca [2] 57 cd [2] 4b e2 }

  condition:
    any of them
}