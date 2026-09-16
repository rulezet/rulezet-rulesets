rule TTP_XOR_QUAD_CurrentVersionRun_c462 {
  strings:
    $key_c462 = { 97 0d [2] b3 03 [2] 98 2f [2] b6 0d [2] a2 16 [2] ad 0c [2] b3 11 [2] b1 10 [2] aa 16 [2] b6 11 [2] aa 3e }

  condition:
    any of them
}