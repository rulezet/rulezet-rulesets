rule TTP_XOR_QUAD_CurrentVersionRun_ddf9 {
  strings:
    $key_ddf9 = { 8e 96 [2] aa 98 [2] 81 b4 [2] af 96 [2] bb 8d [2] b4 97 [2] aa 8a [2] a8 8b [2] b3 8d [2] af 8a [2] b3 a5 }

  condition:
    any of them
}