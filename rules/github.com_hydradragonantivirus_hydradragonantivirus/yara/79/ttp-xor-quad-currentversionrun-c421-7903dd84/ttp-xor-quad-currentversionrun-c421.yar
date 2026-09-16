rule TTP_XOR_QUAD_CurrentVersionRun_c421 {
  strings:
    $key_c421 = { 97 4e [2] b3 40 [2] 98 6c [2] b6 4e [2] a2 55 [2] ad 4f [2] b3 52 [2] b1 53 [2] aa 55 [2] b6 52 [2] aa 7d }

  condition:
    any of them
}