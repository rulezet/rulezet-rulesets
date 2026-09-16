rule TTP_XOR_QUAD_CurrentVersionRun_3db4 {
  strings:
    $key_3db4 = { 6e db [2] 4a d5 [2] 61 f9 [2] 4f db [2] 5b c0 [2] 54 da [2] 4a c7 [2] 48 c6 [2] 53 c0 [2] 4f c7 [2] 53 e8 }

  condition:
    any of them
}