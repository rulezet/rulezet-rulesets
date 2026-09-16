rule TTP_XOR_QUAD_CurrentVersionRun_c506 {
  strings:
    $key_c506 = { 96 69 [2] b2 67 [2] 99 4b [2] b7 69 [2] a3 72 [2] ac 68 [2] b2 75 [2] b0 74 [2] ab 72 [2] b7 75 [2] ab 5a }

  condition:
    any of them
}