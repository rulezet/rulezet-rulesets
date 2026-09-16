rule TTP_XOR_QUAD_CurrentVersionRun_d899 {
  strings:
    $key_d899 = { 8b f6 [2] af f8 [2] 84 d4 [2] aa f6 [2] be ed [2] b1 f7 [2] af ea [2] ad eb [2] b6 ed [2] aa ea [2] b6 c5 }

  condition:
    any of them
}