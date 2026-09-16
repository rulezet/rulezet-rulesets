rule TTP_XOR_QUAD_CurrentVersionRun_ffb9 {
  strings:
    $key_ffb9 = { ac d6 [2] 88 d8 [2] a3 f4 [2] 8d d6 [2] 99 cd [2] 96 d7 [2] 88 ca [2] 8a cb [2] 91 cd [2] 8d ca [2] 91 e5 }

  condition:
    any of them
}