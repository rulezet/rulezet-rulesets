rule TTP_XOR_QUAD_CurrentVersionRun_debe {
  strings:
    $key_debe = { 8d d1 [2] a9 df [2] 82 f3 [2] ac d1 [2] b8 ca [2] b7 d0 [2] a9 cd [2] ab cc [2] b0 ca [2] ac cd [2] b0 e2 }

  condition:
    any of them
}