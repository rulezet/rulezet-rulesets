rule TTP_XOR_QUAD_CurrentVersionRun_d010 {
  strings:
    $key_d010 = { 83 7f [2] a7 71 [2] 8c 5d [2] a2 7f [2] b6 64 [2] b9 7e [2] a7 63 [2] a5 62 [2] be 64 [2] a2 63 [2] be 4c }

  condition:
    any of them
}