rule TTP_XOR_QUAD_CurrentVersionRun_ddb1 {
  strings:
    $key_ddb1 = { 8e de [2] aa d0 [2] 81 fc [2] af de [2] bb c5 [2] b4 df [2] aa c2 [2] a8 c3 [2] b3 c5 [2] af c2 [2] b3 ed }

  condition:
    any of them
}