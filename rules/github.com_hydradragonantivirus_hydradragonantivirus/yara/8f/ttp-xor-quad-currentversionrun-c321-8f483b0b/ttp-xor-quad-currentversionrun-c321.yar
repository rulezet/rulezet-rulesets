rule TTP_XOR_QUAD_CurrentVersionRun_c321 {
  strings:
    $key_c321 = { 90 4e [2] b4 40 [2] 9f 6c [2] b1 4e [2] a5 55 [2] aa 4f [2] b4 52 [2] b6 53 [2] ad 55 [2] b1 52 [2] ad 7d }

  condition:
    any of them
}