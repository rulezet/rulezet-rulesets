rule TTP_XOR_QUAD_CurrentVersionRun_c43d {
  strings:
    $key_c43d = { 97 52 [2] b3 5c [2] 98 70 [2] b6 52 [2] a2 49 [2] ad 53 [2] b3 4e [2] b1 4f [2] aa 49 [2] b6 4e [2] aa 61 }

  condition:
    any of them
}