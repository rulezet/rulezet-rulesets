rule TTP_XOR_QUAD_CurrentVersionRun_c0fd {
  strings:
    $key_c0fd = { 93 92 [2] b7 9c [2] 9c b0 [2] b2 92 [2] a6 89 [2] a9 93 [2] b7 8e [2] b5 8f [2] ae 89 [2] b2 8e [2] ae a1 }

  condition:
    any of them
}