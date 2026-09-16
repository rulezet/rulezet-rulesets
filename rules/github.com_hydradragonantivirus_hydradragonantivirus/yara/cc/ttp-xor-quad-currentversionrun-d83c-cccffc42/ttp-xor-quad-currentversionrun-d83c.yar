rule TTP_XOR_QUAD_CurrentVersionRun_d83c {
  strings:
    $key_d83c = { 8b 53 [2] af 5d [2] 84 71 [2] aa 53 [2] be 48 [2] b1 52 [2] af 4f [2] ad 4e [2] b6 48 [2] aa 4f [2] b6 60 }

  condition:
    any of them
}