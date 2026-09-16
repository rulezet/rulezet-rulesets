rule TTP_XOR_QUAD_CurrentVersionRun_dd62 {
  strings:
    $key_dd62 = { 8e 0d [2] aa 03 [2] 81 2f [2] af 0d [2] bb 16 [2] b4 0c [2] aa 11 [2] a8 10 [2] b3 16 [2] af 11 [2] b3 3e }

  condition:
    any of them
}