rule TTP_XOR_QUAD_CurrentVersionRun_c511 {
  strings:
    $key_c511 = { 96 7e [2] b2 70 [2] 99 5c [2] b7 7e [2] a3 65 [2] ac 7f [2] b2 62 [2] b0 63 [2] ab 65 [2] b7 62 [2] ab 4d }

  condition:
    any of them
}