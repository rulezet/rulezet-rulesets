rule TTP_XOR_QUAD_CurrentVersionRun_d732 {
  strings:
    $key_d732 = { 84 5d [2] a0 53 [2] 8b 7f [2] a5 5d [2] b1 46 [2] be 5c [2] a0 41 [2] a2 40 [2] b9 46 [2] a5 41 [2] b9 6e }

  condition:
    any of them
}