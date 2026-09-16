rule TTP_XOR_QUAD_CurrentVersionRun_c411 {
  strings:
    $key_c411 = { 97 7e [2] b3 70 [2] 98 5c [2] b6 7e [2] a2 65 [2] ad 7f [2] b3 62 [2] b1 63 [2] aa 65 [2] b6 62 [2] aa 4d }

  condition:
    any of them
}