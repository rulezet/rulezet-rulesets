rule TTP_XOR_QUAD_CurrentVersionRun_d8cc {
  strings:
    $key_d8cc = { 8b a3 [2] af ad [2] 84 81 [2] aa a3 [2] be b8 [2] b1 a2 [2] af bf [2] ad be [2] b6 b8 [2] aa bf [2] b6 90 }

  condition:
    any of them
}