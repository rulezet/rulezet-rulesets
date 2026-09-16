rule TTP_XOR_QUAD_CurrentVersionRun_de21 {
  strings:
    $key_de21 = { 8d 4e [2] a9 40 [2] 82 6c [2] ac 4e [2] b8 55 [2] b7 4f [2] a9 52 [2] ab 53 [2] b0 55 [2] ac 52 [2] b0 7d }

  condition:
    any of them
}