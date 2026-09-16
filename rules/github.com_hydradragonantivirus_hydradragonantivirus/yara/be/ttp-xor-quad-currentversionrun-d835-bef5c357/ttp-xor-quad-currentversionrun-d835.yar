rule TTP_XOR_QUAD_CurrentVersionRun_d835 {
  strings:
    $key_d835 = { 8b 5a [2] af 54 [2] 84 78 [2] aa 5a [2] be 41 [2] b1 5b [2] af 46 [2] ad 47 [2] b6 41 [2] aa 46 [2] b6 69 }

  condition:
    any of them
}