rule TTP_XOR_QUAD_CurrentVersionRun_c46d {
  strings:
    $key_c46d = { 97 02 [2] b3 0c [2] 98 20 [2] b6 02 [2] a2 19 [2] ad 03 [2] b3 1e [2] b1 1f [2] aa 19 [2] b6 1e [2] aa 31 }

  condition:
    any of them
}