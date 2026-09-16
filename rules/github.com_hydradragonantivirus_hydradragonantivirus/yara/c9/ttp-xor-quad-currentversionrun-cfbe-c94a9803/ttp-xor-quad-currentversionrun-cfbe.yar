rule TTP_XOR_QUAD_CurrentVersionRun_cfbe {
  strings:
    $key_cfbe = { 9c d1 [2] b8 df [2] 93 f3 [2] bd d1 [2] a9 ca [2] a6 d0 [2] b8 cd [2] ba cc [2] a1 ca [2] bd cd [2] a1 e2 }

  condition:
    any of them
}