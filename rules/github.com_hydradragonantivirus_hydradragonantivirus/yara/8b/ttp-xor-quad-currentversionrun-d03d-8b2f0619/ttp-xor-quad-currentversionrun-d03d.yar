rule TTP_XOR_QUAD_CurrentVersionRun_d03d {
  strings:
    $key_d03d = { 83 52 [2] a7 5c [2] 8c 70 [2] a2 52 [2] b6 49 [2] b9 53 [2] a7 4e [2] a5 4f [2] be 49 [2] a2 4e [2] be 61 }

  condition:
    any of them
}