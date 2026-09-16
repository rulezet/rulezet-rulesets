rule TTP_XOR_QUAD_CurrentVersionRun_c401 {
  strings:
    $key_c401 = { 97 6e [2] b3 60 [2] 98 4c [2] b6 6e [2] a2 75 [2] ad 6f [2] b3 72 [2] b1 73 [2] aa 75 [2] b6 72 [2] aa 5d }

  condition:
    any of them
}