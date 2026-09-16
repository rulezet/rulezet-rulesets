rule TTP_XOR_QUAD_CurrentVersionRun_fdb1 {
  strings:
    $key_fdb1 = { ae de [2] 8a d0 [2] a1 fc [2] 8f de [2] 9b c5 [2] 94 df [2] 8a c2 [2] 88 c3 [2] 93 c5 [2] 8f c2 [2] 93 ed }

  condition:
    any of them
}