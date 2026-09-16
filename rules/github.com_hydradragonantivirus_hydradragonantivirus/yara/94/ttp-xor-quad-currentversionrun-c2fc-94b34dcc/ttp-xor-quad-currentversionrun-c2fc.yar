rule TTP_XOR_QUAD_CurrentVersionRun_c2fc {
  strings:
    $key_c2fc = { 91 93 [2] b5 9d [2] 9e b1 [2] b0 93 [2] a4 88 [2] ab 92 [2] b5 8f [2] b7 8e [2] ac 88 [2] b0 8f [2] ac a0 }

  condition:
    any of them
}