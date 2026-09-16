rule TTP_XOR_QUAD_CurrentVersionRun_f6be {
  strings:
    $key_f6be = { a5 d1 [2] 81 df [2] aa f3 [2] 84 d1 [2] 90 ca [2] 9f d0 [2] 81 cd [2] 83 cc [2] 98 ca [2] 84 cd [2] 98 e2 }

  condition:
    any of them
}