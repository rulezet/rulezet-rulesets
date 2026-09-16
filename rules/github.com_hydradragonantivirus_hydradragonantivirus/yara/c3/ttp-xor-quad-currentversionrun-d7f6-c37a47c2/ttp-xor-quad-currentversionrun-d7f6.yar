rule TTP_XOR_QUAD_CurrentVersionRun_d7f6 {
  strings:
    $key_d7f6 = { 84 99 [2] a0 97 [2] 8b bb [2] a5 99 [2] b1 82 [2] be 98 [2] a0 85 [2] a2 84 [2] b9 82 [2] a5 85 [2] b9 aa }

  condition:
    any of them
}