rule TTP_XOR_QUAD_CurrentVersionRun_afbe {
  strings:
    $key_afbe = { fc d1 [2] d8 df [2] f3 f3 [2] dd d1 [2] c9 ca [2] c6 d0 [2] d8 cd [2] da cc [2] c1 ca [2] dd cd [2] c1 e2 }

  condition:
    any of them
}