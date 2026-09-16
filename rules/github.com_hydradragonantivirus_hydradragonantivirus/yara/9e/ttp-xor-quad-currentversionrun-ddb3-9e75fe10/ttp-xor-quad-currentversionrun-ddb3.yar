rule TTP_XOR_QUAD_CurrentVersionRun_ddb3 {
  strings:
    $key_ddb3 = { 8e dc [2] aa d2 [2] 81 fe [2] af dc [2] bb c7 [2] b4 dd [2] aa c0 [2] a8 c1 [2] b3 c7 [2] af c0 [2] b3 ef }

  condition:
    any of them
}