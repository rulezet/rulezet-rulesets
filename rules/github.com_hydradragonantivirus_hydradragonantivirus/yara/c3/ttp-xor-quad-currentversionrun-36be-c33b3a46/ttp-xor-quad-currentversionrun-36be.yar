rule TTP_XOR_QUAD_CurrentVersionRun_36be {
  strings:
    $key_36be = { 65 d1 [2] 41 df [2] 6a f3 [2] 44 d1 [2] 50 ca [2] 5f d0 [2] 41 cd [2] 43 cc [2] 58 ca [2] 44 cd [2] 58 e2 }

  condition:
    any of them
}