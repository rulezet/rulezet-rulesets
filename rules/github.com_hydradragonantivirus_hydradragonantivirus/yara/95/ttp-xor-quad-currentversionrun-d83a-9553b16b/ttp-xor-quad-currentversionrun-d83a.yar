rule TTP_XOR_QUAD_CurrentVersionRun_d83a {
  strings:
    $key_d83a = { 8b 55 [2] af 5b [2] 84 77 [2] aa 55 [2] be 4e [2] b1 54 [2] af 49 [2] ad 48 [2] b6 4e [2] aa 49 [2] b6 66 }

  condition:
    any of them
}