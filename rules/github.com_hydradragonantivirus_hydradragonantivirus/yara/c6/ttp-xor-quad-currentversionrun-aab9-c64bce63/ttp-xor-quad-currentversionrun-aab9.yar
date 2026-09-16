rule TTP_XOR_QUAD_CurrentVersionRun_aab9 {
  strings:
    $key_aab9 = { f9 d6 [2] dd d8 [2] f6 f4 [2] d8 d6 [2] cc cd [2] c3 d7 [2] dd ca [2] df cb [2] c4 cd [2] d8 ca [2] c4 e5 }

  condition:
    any of them
}