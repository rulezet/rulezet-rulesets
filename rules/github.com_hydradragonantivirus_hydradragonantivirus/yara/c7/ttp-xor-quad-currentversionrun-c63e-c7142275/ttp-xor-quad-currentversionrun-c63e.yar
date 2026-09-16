rule TTP_XOR_QUAD_CurrentVersionRun_c63e {
  strings:
    $key_c63e = { 95 51 [2] b1 5f [2] 9a 73 [2] b4 51 [2] a0 4a [2] af 50 [2] b1 4d [2] b3 4c [2] a8 4a [2] b4 4d [2] a8 62 }

  condition:
    any of them
}