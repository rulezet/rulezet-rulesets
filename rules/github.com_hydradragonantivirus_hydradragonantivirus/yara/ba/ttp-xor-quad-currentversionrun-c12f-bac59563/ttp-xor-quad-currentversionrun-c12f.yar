rule TTP_XOR_QUAD_CurrentVersionRun_c12f {
  strings:
    $key_c12f = { 92 40 [2] b6 4e [2] 9d 62 [2] b3 40 [2] a7 5b [2] a8 41 [2] b6 5c [2] b4 5d [2] af 5b [2] b3 5c [2] af 73 }

  condition:
    any of them
}