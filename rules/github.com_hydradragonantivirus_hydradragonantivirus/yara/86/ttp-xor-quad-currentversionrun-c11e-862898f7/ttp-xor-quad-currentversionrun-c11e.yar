rule TTP_XOR_QUAD_CurrentVersionRun_c11e {
  strings:
    $key_c11e = { 92 71 [2] b6 7f [2] 9d 53 [2] b3 71 [2] a7 6a [2] a8 70 [2] b6 6d [2] b4 6c [2] af 6a [2] b3 6d [2] af 42 }

  condition:
    any of them
}