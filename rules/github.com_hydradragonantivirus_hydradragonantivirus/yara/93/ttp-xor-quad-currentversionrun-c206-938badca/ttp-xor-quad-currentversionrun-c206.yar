rule TTP_XOR_QUAD_CurrentVersionRun_c206 {
  strings:
    $key_c206 = { 91 69 [2] b5 67 [2] 9e 4b [2] b0 69 [2] a4 72 [2] ab 68 [2] b5 75 [2] b7 74 [2] ac 72 [2] b0 75 [2] ac 5a }

  condition:
    any of them
}