rule TTP_XOR_QUAD_CurrentVersionRun_c5f7 {
  strings:
    $key_c5f7 = { 96 98 [2] b2 96 [2] 99 ba [2] b7 98 [2] a3 83 [2] ac 99 [2] b2 84 [2] b0 85 [2] ab 83 [2] b7 84 [2] ab ab }

  condition:
    any of them
}