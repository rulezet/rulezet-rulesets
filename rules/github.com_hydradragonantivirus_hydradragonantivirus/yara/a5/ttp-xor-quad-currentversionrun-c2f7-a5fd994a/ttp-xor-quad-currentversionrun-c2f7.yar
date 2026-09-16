rule TTP_XOR_QUAD_CurrentVersionRun_c2f7 {
  strings:
    $key_c2f7 = { 91 98 [2] b5 96 [2] 9e ba [2] b0 98 [2] a4 83 [2] ab 99 [2] b5 84 [2] b7 85 [2] ac 83 [2] b0 84 [2] ac ab }

  condition:
    any of them
}