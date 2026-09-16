rule TTP_XOR_QUAD_CurrentVersionRun_cbbe {
  strings:
    $key_cbbe = { 98 d1 [2] bc df [2] 97 f3 [2] b9 d1 [2] ad ca [2] a2 d0 [2] bc cd [2] be cc [2] a5 ca [2] b9 cd [2] a5 e2 }

  condition:
    any of them
}