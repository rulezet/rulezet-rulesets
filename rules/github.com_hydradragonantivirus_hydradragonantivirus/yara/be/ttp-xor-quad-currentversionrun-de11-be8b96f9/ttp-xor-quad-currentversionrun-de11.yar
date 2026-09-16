rule TTP_XOR_QUAD_CurrentVersionRun_de11 {
  strings:
    $key_de11 = { 8d 7e [2] a9 70 [2] 82 5c [2] ac 7e [2] b8 65 [2] b7 7f [2] a9 62 [2] ab 63 [2] b0 65 [2] ac 62 [2] b0 4d }

  condition:
    any of them
}