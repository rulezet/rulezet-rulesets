rule TTP_XOR_QUAD_CurrentVersionRun_dcb2 {
  strings:
    $key_dcb2 = { 8f dd [2] ab d3 [2] 80 ff [2] ae dd [2] ba c6 [2] b5 dc [2] ab c1 [2] a9 c0 [2] b2 c6 [2] ae c1 [2] b2 ee }

  condition:
    any of them
}