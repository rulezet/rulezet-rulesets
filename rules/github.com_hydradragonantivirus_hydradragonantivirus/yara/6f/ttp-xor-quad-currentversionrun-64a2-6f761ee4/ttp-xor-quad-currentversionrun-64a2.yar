rule TTP_XOR_QUAD_CurrentVersionRun_64a2 {
  strings:
    $key_64a2 = { 37 cd [2] 13 c3 [2] 38 ef [2] 16 cd [2] 02 d6 [2] 0d cc [2] 13 d1 [2] 11 d0 [2] 0a d6 [2] 16 d1 [2] 0a fe }

  condition:
    any of them
}