rule TTP_XOR_QUAD_CurrentVersionRun_4bbe {
  strings:
    $key_4bbe = { 18 d1 [2] 3c df [2] 17 f3 [2] 39 d1 [2] 2d ca [2] 22 d0 [2] 3c cd [2] 3e cc [2] 25 ca [2] 39 cd [2] 25 e2 }

  condition:
    any of them
}