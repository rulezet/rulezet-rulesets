rule TTP_XOR_QUAD_CurrentVersionRun_4abe {
  strings:
    $key_4abe = { 19 d1 [2] 3d df [2] 16 f3 [2] 38 d1 [2] 2c ca [2] 23 d0 [2] 3d cd [2] 3f cc [2] 24 ca [2] 38 cd [2] 24 e2 }

  condition:
    any of them
}