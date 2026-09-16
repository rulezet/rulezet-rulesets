rule TTP_XOR_QUAD_CurrentVersionRun_c4ed {
  strings:
    $key_c4ed = { 97 82 [2] b3 8c [2] 98 a0 [2] b6 82 [2] a2 99 [2] ad 83 [2] b3 9e [2] b1 9f [2] aa 99 [2] b6 9e [2] aa b1 }

  condition:
    any of them
}