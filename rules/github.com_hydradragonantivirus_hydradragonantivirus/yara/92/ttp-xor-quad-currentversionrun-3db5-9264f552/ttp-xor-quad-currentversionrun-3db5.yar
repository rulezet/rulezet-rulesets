rule TTP_XOR_QUAD_CurrentVersionRun_3db5 {
  strings:
    $key_3db5 = { 6e da [2] 4a d4 [2] 61 f8 [2] 4f da [2] 5b c1 [2] 54 db [2] 4a c6 [2] 48 c7 [2] 53 c1 [2] 4f c6 [2] 53 e9 }

  condition:
    any of them
}