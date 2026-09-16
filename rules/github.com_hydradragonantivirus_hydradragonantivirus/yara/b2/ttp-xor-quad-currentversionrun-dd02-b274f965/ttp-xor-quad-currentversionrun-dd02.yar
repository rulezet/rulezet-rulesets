rule TTP_XOR_QUAD_CurrentVersionRun_dd02 {
  strings:
    $key_dd02 = { 8e 6d [2] aa 63 [2] 81 4f [2] af 6d [2] bb 76 [2] b4 6c [2] aa 71 [2] a8 70 [2] b3 76 [2] af 71 [2] b3 5e }

  condition:
    any of them
}