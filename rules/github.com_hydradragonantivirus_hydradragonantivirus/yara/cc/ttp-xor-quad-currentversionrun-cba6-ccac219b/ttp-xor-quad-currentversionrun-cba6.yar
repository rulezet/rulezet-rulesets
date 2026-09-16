rule TTP_XOR_QUAD_CurrentVersionRun_cba6 {
  strings:
    $key_cba6 = { 98 c9 [2] bc c7 [2] 97 eb [2] b9 c9 [2] ad d2 [2] a2 c8 [2] bc d5 [2] be d4 [2] a5 d2 [2] b9 d5 [2] a5 fa }

  condition:
    any of them
}