rule TTP_XOR_QUAD_CurrentVersionRun_d722 {
  strings:
    $key_d722 = { 84 4d [2] a0 43 [2] 8b 6f [2] a5 4d [2] b1 56 [2] be 4c [2] a0 51 [2] a2 50 [2] b9 56 [2] a5 51 [2] b9 7e }

  condition:
    any of them
}