rule TTP_XOR_QUAD_CurrentVersionRun_c4ef {
  strings:
    $key_c4ef = { 97 80 [2] b3 8e [2] 98 a2 [2] b6 80 [2] a2 9b [2] ad 81 [2] b3 9c [2] b1 9d [2] aa 9b [2] b6 9c [2] aa b3 }

  condition:
    any of them
}