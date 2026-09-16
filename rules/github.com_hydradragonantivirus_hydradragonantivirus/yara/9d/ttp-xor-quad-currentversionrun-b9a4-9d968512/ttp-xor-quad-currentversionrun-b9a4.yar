rule TTP_XOR_QUAD_CurrentVersionRun_b9a4 {
  strings:
    $key_b9a4 = { ea cb [2] ce c5 [2] e5 e9 [2] cb cb [2] df d0 [2] d0 ca [2] ce d7 [2] cc d6 [2] d7 d0 [2] cb d7 [2] d7 f8 }

  condition:
    any of them
}