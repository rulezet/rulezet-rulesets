rule TTP_XOR_QUAD_CurrentVersionRun_51be {
  strings:
    $key_51be = { 02 d1 [2] 26 df [2] 0d f3 [2] 23 d1 [2] 37 ca [2] 38 d0 [2] 26 cd [2] 24 cc [2] 3f ca [2] 23 cd [2] 3f e2 }

  condition:
    any of them
}