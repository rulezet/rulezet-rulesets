rule TTP_XOR_QUAD_CurrentVersionRun_d412 {
  strings:
    $key_d412 = { 87 7d [2] a3 73 [2] 88 5f [2] a6 7d [2] b2 66 [2] bd 7c [2] a3 61 [2] a1 60 [2] ba 66 [2] a6 61 [2] ba 4e }

  condition:
    any of them
}