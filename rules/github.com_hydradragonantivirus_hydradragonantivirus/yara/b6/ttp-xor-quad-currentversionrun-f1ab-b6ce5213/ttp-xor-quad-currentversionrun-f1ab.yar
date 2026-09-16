rule TTP_XOR_QUAD_CurrentVersionRun_f1ab {
  strings:
    $key_f1ab = { a2 c4 [2] 86 ca [2] ad e6 [2] 83 c4 [2] 97 df [2] 98 c5 [2] 86 d8 [2] 84 d9 [2] 9f df [2] 83 d8 [2] 9f f7 }

  condition:
    any of them
}