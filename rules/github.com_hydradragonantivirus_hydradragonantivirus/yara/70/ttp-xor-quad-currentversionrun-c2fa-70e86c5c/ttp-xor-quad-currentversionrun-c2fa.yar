rule TTP_XOR_QUAD_CurrentVersionRun_c2fa {
  strings:
    $key_c2fa = { 91 95 [2] b5 9b [2] 9e b7 [2] b0 95 [2] a4 8e [2] ab 94 [2] b5 89 [2] b7 88 [2] ac 8e [2] b0 89 [2] ac a6 }

  condition:
    any of them
}