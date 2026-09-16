rule TTP_XOR_QUAD_CurrentVersionRun_c432 {
  strings:
    $key_c432 = { 97 5d [2] b3 53 [2] 98 7f [2] b6 5d [2] a2 46 [2] ad 5c [2] b3 41 [2] b1 40 [2] aa 46 [2] b6 41 [2] aa 6e }

  condition:
    any of them
}