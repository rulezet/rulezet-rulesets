rule TTP_XOR_QUAD_CurrentVersionRun_d012 {
  strings:
    $key_d012 = { 83 7d [2] a7 73 [2] 8c 5f [2] a2 7d [2] b6 66 [2] b9 7c [2] a7 61 [2] a5 60 [2] be 66 [2] a2 61 [2] be 4e }

  condition:
    any of them
}