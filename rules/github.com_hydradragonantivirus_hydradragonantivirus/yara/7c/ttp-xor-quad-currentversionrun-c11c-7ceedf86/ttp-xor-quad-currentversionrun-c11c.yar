rule TTP_XOR_QUAD_CurrentVersionRun_c11c {
  strings:
    $key_c11c = { 92 73 [2] b6 7d [2] 9d 51 [2] b3 73 [2] a7 68 [2] a8 72 [2] b6 6f [2] b4 6e [2] af 68 [2] b3 6f [2] af 40 }

  condition:
    any of them
}