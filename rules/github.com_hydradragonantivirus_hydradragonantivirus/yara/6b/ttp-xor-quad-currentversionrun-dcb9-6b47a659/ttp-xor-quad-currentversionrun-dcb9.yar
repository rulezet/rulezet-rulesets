rule TTP_XOR_QUAD_CurrentVersionRun_dcb9 {
  strings:
    $key_dcb9 = { 8f d6 [2] ab d8 [2] 80 f4 [2] ae d6 [2] ba cd [2] b5 d7 [2] ab ca [2] a9 cb [2] b2 cd [2] ae ca [2] b2 e5 }

  condition:
    any of them
}