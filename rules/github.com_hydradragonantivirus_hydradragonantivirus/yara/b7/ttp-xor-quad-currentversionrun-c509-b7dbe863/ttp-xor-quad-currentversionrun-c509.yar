rule TTP_XOR_QUAD_CurrentVersionRun_c509 {
  strings:
    $key_c509 = { 96 66 [2] b2 68 [2] 99 44 [2] b7 66 [2] a3 7d [2] ac 67 [2] b2 7a [2] b0 7b [2] ab 7d [2] b7 7a [2] ab 55 }

  condition:
    any of them
}