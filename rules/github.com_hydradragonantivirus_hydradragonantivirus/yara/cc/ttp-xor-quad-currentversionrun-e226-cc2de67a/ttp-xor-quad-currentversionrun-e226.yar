rule TTP_XOR_QUAD_CurrentVersionRun_e226 {
  strings:
    $key_e226 = { b1 49 [2] 95 47 [2] be 6b [2] 90 49 [2] 84 52 [2] 8b 48 [2] 95 55 [2] 97 54 [2] 8c 52 [2] 90 55 [2] 8c 7a }

  condition:
    any of them
}