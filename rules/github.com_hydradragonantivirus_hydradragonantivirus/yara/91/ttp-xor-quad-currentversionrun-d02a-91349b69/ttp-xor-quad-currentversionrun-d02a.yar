rule TTP_XOR_QUAD_CurrentVersionRun_d02a {
  strings:
    $key_d02a = { 83 45 [2] a7 4b [2] 8c 67 [2] a2 45 [2] b6 5e [2] b9 44 [2] a7 59 [2] a5 58 [2] be 5e [2] a2 59 [2] be 76 }

  condition:
    any of them
}