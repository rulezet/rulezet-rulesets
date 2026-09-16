rule TTP_XOR_QUAD_CurrentVersionRun_d062 {
  strings:
    $key_d062 = { 83 0d [2] a7 03 [2] 8c 2f [2] a2 0d [2] b6 16 [2] b9 0c [2] a7 11 [2] a5 10 [2] be 16 [2] a2 11 [2] be 3e }

  condition:
    any of them
}