rule TTP_XOR_QUAD_CurrentVersionRun_d0f9 {
  strings:
    $key_d0f9 = { 83 96 [2] a7 98 [2] 8c b4 [2] a2 96 [2] b6 8d [2] b9 97 [2] a7 8a [2] a5 8b [2] be 8d [2] a2 8a [2] be a5 }

  condition:
    any of them
}