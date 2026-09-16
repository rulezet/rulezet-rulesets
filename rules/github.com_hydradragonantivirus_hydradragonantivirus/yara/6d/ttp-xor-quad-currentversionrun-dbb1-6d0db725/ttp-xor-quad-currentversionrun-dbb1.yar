rule TTP_XOR_QUAD_CurrentVersionRun_dbb1 {
  strings:
    $key_dbb1 = { 88 de [2] ac d0 [2] 87 fc [2] a9 de [2] bd c5 [2] b2 df [2] ac c2 [2] ae c3 [2] b5 c5 [2] a9 c2 [2] b5 ed }

  condition:
    any of them
}