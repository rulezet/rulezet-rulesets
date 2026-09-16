rule TTP_XOR_QUAD_CurrentVersionRun_c54b {
  strings:
    $key_c54b = { 96 24 [2] b2 2a [2] 99 06 [2] b7 24 [2] a3 3f [2] ac 25 [2] b2 38 [2] b0 39 [2] ab 3f [2] b7 38 [2] ab 17 }

  condition:
    any of them
}