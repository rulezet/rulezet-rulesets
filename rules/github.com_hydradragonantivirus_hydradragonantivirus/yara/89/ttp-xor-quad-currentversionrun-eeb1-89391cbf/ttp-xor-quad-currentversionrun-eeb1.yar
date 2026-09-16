rule TTP_XOR_QUAD_CurrentVersionRun_eeb1 {
  strings:
    $key_eeb1 = { bd de [2] 99 d0 [2] b2 fc [2] 9c de [2] 88 c5 [2] 87 df [2] 99 c2 [2] 9b c3 [2] 80 c5 [2] 9c c2 [2] 80 ed }

  condition:
    any of them
}