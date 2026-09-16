rule TTP_XOR_QUAD_CurrentVersionRun_c52b {
  strings:
    $key_c52b = { 96 44 [2] b2 4a [2] 99 66 [2] b7 44 [2] a3 5f [2] ac 45 [2] b2 58 [2] b0 59 [2] ab 5f [2] b7 58 [2] ab 77 }

  condition:
    any of them
}