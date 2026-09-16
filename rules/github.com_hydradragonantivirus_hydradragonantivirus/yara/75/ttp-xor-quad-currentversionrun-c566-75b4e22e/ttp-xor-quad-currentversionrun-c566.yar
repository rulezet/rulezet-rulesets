rule TTP_XOR_QUAD_CurrentVersionRun_c566 {
  strings:
    $key_c566 = { 96 09 [2] b2 07 [2] 99 2b [2] b7 09 [2] a3 12 [2] ac 08 [2] b2 15 [2] b0 14 [2] ab 12 [2] b7 15 [2] ab 3a }

  condition:
    any of them
}