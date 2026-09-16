rule TTP_XOR_QUAD_CurrentVersionRun_eab1 {
  strings:
    $key_eab1 = { b9 de [2] 9d d0 [2] b6 fc [2] 98 de [2] 8c c5 [2] 83 df [2] 9d c2 [2] 9f c3 [2] 84 c5 [2] 98 c2 [2] 84 ed }

  condition:
    any of them
}