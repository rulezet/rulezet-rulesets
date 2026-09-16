rule TTP_XOR_QUAD_CurrentVersionRun_11be {
  strings:
    $key_11be = { 42 d1 [2] 66 df [2] 4d f3 [2] 63 d1 [2] 77 ca [2] 78 d0 [2] 66 cd [2] 64 cc [2] 7f ca [2] 63 cd [2] 7f e2 }

  condition:
    any of them
}