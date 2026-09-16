rule TTP_XOR_QUAD_CurrentVersionRun_e492 {
  strings:
    $key_e492 = { b7 fd [2] 93 f3 [2] b8 df [2] 96 fd [2] 82 e6 [2] 8d fc [2] 93 e1 [2] 91 e0 [2] 8a e6 [2] 96 e1 [2] 8a ce }

  condition:
    any of them
}