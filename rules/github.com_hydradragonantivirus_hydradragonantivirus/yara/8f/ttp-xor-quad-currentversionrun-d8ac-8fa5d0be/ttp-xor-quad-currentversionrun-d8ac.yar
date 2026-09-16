rule TTP_XOR_QUAD_CurrentVersionRun_d8ac {
  strings:
    $key_d8ac = { 8b c3 [2] af cd [2] 84 e1 [2] aa c3 [2] be d8 [2] b1 c2 [2] af df [2] ad de [2] b6 d8 [2] aa df [2] b6 f0 }

  condition:
    any of them
}