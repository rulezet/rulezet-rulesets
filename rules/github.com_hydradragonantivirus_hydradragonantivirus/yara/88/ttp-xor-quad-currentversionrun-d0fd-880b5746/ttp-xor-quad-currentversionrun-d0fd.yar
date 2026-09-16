rule TTP_XOR_QUAD_CurrentVersionRun_d0fd {
  strings:
    $key_d0fd = { 83 92 [2] a7 9c [2] 8c b0 [2] a2 92 [2] b6 89 [2] b9 93 [2] a7 8e [2] a5 8f [2] be 89 [2] a2 8e [2] be a1 }

  condition:
    any of them
}