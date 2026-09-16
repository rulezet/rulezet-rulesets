rule TTP_XOR_QUAD_CurrentVersionRun_d816 {
  strings:
    $key_d816 = { 8b 79 [2] af 77 [2] 84 5b [2] aa 79 [2] be 62 [2] b1 78 [2] af 65 [2] ad 64 [2] b6 62 [2] aa 65 [2] b6 4a }

  condition:
    any of them
}