rule TTP_XOR_QUAD_CurrentVersionRun_c57b {
  strings:
    $key_c57b = { 96 14 [2] b2 1a [2] 99 36 [2] b7 14 [2] a3 0f [2] ac 15 [2] b2 08 [2] b0 09 [2] ab 0f [2] b7 08 [2] ab 27 }

  condition:
    any of them
}