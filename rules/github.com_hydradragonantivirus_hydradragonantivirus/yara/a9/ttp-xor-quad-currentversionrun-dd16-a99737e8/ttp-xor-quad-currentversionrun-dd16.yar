rule TTP_XOR_QUAD_CurrentVersionRun_dd16 {
  strings:
    $key_dd16 = { 8e 79 [2] aa 77 [2] 81 5b [2] af 79 [2] bb 62 [2] b4 78 [2] aa 65 [2] a8 64 [2] b3 62 [2] af 65 [2] b3 4a }

  condition:
    any of them
}