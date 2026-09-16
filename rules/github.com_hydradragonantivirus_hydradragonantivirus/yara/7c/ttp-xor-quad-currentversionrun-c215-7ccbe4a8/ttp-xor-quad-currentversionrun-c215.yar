rule TTP_XOR_QUAD_CurrentVersionRun_c215 {
  strings:
    $key_c215 = { 91 7a [2] b5 74 [2] 9e 58 [2] b0 7a [2] a4 61 [2] ab 7b [2] b5 66 [2] b7 67 [2] ac 61 [2] b0 66 [2] ac 49 }

  condition:
    any of them
}