rule TTP_XOR_QUAD_CurrentVersionRun_3db6 {
  strings:
    $key_3db6 = { 6e d9 [2] 4a d7 [2] 61 fb [2] 4f d9 [2] 5b c2 [2] 54 d8 [2] 4a c5 [2] 48 c4 [2] 53 c2 [2] 4f c5 [2] 53 ea }

  condition:
    any of them
}