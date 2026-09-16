rule TTP_XOR_QUAD_CurrentVersionRun_d022 {
  strings:
    $key_d022 = { 83 4d [2] a7 43 [2] 8c 6f [2] a2 4d [2] b6 56 [2] b9 4c [2] a7 51 [2] a5 50 [2] be 56 [2] a2 51 [2] be 7e }

  condition:
    any of them
}