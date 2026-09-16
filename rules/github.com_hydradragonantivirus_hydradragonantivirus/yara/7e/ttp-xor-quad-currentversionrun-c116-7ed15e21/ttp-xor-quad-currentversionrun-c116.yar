rule TTP_XOR_QUAD_CurrentVersionRun_c116 {
  strings:
    $key_c116 = { 92 79 [2] b6 77 [2] 9d 5b [2] b3 79 [2] a7 62 [2] a8 78 [2] b6 65 [2] b4 64 [2] af 62 [2] b3 65 [2] af 4a }

  condition:
    any of them
}