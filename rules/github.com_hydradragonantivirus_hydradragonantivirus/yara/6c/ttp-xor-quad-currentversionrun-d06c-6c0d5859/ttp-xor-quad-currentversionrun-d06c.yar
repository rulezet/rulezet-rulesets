rule TTP_XOR_QUAD_CurrentVersionRun_d06c {
  strings:
    $key_d06c = { 83 03 [2] a7 0d [2] 8c 21 [2] a2 03 [2] b6 18 [2] b9 02 [2] a7 1f [2] a5 1e [2] be 18 [2] a2 1f [2] be 30 }

  condition:
    any of them
}