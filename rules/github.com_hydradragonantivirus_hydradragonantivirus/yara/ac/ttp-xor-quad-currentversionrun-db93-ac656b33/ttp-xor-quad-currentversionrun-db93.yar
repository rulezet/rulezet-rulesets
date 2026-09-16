rule TTP_XOR_QUAD_CurrentVersionRun_db93 {
  strings:
    $key_db93 = { 88 fc [2] ac f2 [2] 87 de [2] a9 fc [2] bd e7 [2] b2 fd [2] ac e0 [2] ae e1 [2] b5 e7 [2] a9 e0 [2] b5 cf }

  condition:
    any of them
}