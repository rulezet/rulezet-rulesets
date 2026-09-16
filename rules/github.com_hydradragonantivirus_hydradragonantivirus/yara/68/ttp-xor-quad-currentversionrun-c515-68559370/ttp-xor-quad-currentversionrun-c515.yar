rule TTP_XOR_QUAD_CurrentVersionRun_c515 {
  strings:
    $key_c515 = { 96 7a [2] b2 74 [2] 99 58 [2] b7 7a [2] a3 61 [2] ac 7b [2] b2 66 [2] b0 67 [2] ab 61 [2] b7 66 [2] ab 49 }

  condition:
    any of them
}