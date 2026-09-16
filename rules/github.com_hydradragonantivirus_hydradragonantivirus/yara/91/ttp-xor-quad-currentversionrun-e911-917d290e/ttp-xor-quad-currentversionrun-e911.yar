rule TTP_XOR_QUAD_CurrentVersionRun_e911 {
  strings:
    $key_e911 = { ba 7e [2] 9e 70 [2] b5 5c [2] 9b 7e [2] 8f 65 [2] 80 7f [2] 9e 62 [2] 9c 63 [2] 87 65 [2] 9b 62 [2] 87 4d }

  condition:
    any of them
}