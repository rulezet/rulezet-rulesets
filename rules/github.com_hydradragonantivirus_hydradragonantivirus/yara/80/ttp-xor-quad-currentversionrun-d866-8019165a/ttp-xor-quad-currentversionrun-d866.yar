rule TTP_XOR_QUAD_CurrentVersionRun_d866 {
  strings:
    $key_d866 = { 8b 09 [2] af 07 [2] 84 2b [2] aa 09 [2] be 12 [2] b1 08 [2] af 15 [2] ad 14 [2] b6 12 [2] aa 15 [2] b6 3a }

  condition:
    any of them
}