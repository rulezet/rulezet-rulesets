rule TTP_XOR_QUAD_CurrentVersionRun_c20a {
  strings:
    $key_c20a = { 91 65 [2] b5 6b [2] 9e 47 [2] b0 65 [2] a4 7e [2] ab 64 [2] b5 79 [2] b7 78 [2] ac 7e [2] b0 79 [2] ac 56 }

  condition:
    any of them
}