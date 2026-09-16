rule TTP_XOR_QUAD_CurrentVersionRun_edb1 {
  strings:
    $key_edb1 = { be de [2] 9a d0 [2] b1 fc [2] 9f de [2] 8b c5 [2] 84 df [2] 9a c2 [2] 98 c3 [2] 83 c5 [2] 9f c2 [2] 83 ed }

  condition:
    any of them
}