rule TTP_XOR_QUAD_CurrentVersionRun_d86c {
  strings:
    $key_d86c = { 8b 03 [2] af 0d [2] 84 21 [2] aa 03 [2] be 18 [2] b1 02 [2] af 1f [2] ad 1e [2] b6 18 [2] aa 1f [2] b6 30 }

  condition:
    any of them
}