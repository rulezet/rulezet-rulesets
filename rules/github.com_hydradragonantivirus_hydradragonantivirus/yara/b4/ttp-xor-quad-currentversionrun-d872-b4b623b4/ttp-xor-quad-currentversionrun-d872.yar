rule TTP_XOR_QUAD_CurrentVersionRun_d872 {
  strings:
    $key_d872 = { 8b 1d [2] af 13 [2] 84 3f [2] aa 1d [2] be 06 [2] b1 1c [2] af 01 [2] ad 00 [2] b6 06 [2] aa 01 [2] b6 2e }

  condition:
    any of them
}