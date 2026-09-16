rule TTP_XOR_QUAD_CurrentVersionRun_c441 {
  strings:
    $key_c441 = { 97 2e [2] b3 20 [2] 98 0c [2] b6 2e [2] a2 35 [2] ad 2f [2] b3 32 [2] b1 33 [2] aa 35 [2] b6 32 [2] aa 1d }

  condition:
    any of them
}