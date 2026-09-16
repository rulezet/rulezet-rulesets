rule TTP_XOR_QUAD_CurrentVersionRun_d876 {
  strings:
    $key_d876 = { 8b 19 [2] af 17 [2] 84 3b [2] aa 19 [2] be 02 [2] b1 18 [2] af 05 [2] ad 04 [2] b6 02 [2] aa 05 [2] b6 2a }

  condition:
    any of them
}