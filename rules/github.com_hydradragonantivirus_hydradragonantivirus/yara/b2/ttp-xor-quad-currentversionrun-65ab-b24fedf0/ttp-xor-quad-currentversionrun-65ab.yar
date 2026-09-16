rule TTP_XOR_QUAD_CurrentVersionRun_65ab {
  strings:
    $key_65ab = { 36 c4 [2] 12 ca [2] 39 e6 [2] 17 c4 [2] 03 df [2] 0c c5 [2] 12 d8 [2] 10 d9 [2] 0b df [2] 17 d8 [2] 0b f7 }

  condition:
    any of them
}