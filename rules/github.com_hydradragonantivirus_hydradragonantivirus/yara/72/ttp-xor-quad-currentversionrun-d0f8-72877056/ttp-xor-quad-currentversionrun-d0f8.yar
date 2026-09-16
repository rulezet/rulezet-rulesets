rule TTP_XOR_QUAD_CurrentVersionRun_d0f8 {
  strings:
    $key_d0f8 = { 83 97 [2] a7 99 [2] 8c b5 [2] a2 97 [2] b6 8c [2] b9 96 [2] a7 8b [2] a5 8a [2] be 8c [2] a2 8b [2] be a4 }

  condition:
    any of them
}