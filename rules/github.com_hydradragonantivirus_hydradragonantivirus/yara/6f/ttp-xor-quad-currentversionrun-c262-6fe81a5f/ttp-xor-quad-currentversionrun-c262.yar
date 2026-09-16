rule TTP_XOR_QUAD_CurrentVersionRun_c262 {
  strings:
    $key_c262 = { 91 0d [2] b5 03 [2] 9e 2f [2] b0 0d [2] a4 16 [2] ab 0c [2] b5 11 [2] b7 10 [2] ac 16 [2] b0 11 [2] ac 3e }

  condition:
    any of them
}