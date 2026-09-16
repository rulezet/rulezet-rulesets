rule TTP_XOR_QUAD_CurrentVersionRun_de22 {
  strings:
    $key_de22 = { 8d 4d [2] a9 43 [2] 82 6f [2] ac 4d [2] b8 56 [2] b7 4c [2] a9 51 [2] ab 50 [2] b0 56 [2] ac 51 [2] b0 7e }

  condition:
    any of them
}