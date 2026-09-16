rule TTP_XOR_QUAD_CurrentVersionRun_deeb {
  strings:
    $key_deeb = { 8d 84 [2] a9 8a [2] 82 a6 [2] ac 84 [2] b8 9f [2] b7 85 [2] a9 98 [2] ab 99 [2] b0 9f [2] ac 98 [2] b0 b7 }

  condition:
    any of them
}