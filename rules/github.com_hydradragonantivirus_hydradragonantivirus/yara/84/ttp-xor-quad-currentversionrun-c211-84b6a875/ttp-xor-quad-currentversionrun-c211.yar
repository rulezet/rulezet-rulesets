rule TTP_XOR_QUAD_CurrentVersionRun_c211 {
  strings:
    $key_c211 = { 91 7e [2] b5 70 [2] 9e 5c [2] b0 7e [2] a4 65 [2] ab 7f [2] b5 62 [2] b7 63 [2] ac 65 [2] b0 62 [2] ac 4d }

  condition:
    any of them
}