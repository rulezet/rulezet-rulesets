rule TTP_XOR_QUAD_CurrentVersionRun_c416 {
  strings:
    $key_c416 = { 97 79 [2] b3 77 [2] 98 5b [2] b6 79 [2] a2 62 [2] ad 78 [2] b3 65 [2] b1 64 [2] aa 62 [2] b6 65 [2] aa 4a }

  condition:
    any of them
}