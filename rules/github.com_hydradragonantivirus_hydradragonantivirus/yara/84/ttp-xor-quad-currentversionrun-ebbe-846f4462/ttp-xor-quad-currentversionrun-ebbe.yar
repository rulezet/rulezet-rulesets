rule TTP_XOR_QUAD_CurrentVersionRun_ebbe {
  strings:
    $key_ebbe = { b8 d1 [2] 9c df [2] b7 f3 [2] 99 d1 [2] 8d ca [2] 82 d0 [2] 9c cd [2] 9e cc [2] 85 ca [2] 99 cd [2] 85 e2 }

  condition:
    any of them
}