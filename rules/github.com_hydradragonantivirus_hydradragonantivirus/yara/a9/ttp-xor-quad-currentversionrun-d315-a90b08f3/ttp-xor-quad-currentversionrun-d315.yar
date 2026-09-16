rule TTP_XOR_QUAD_CurrentVersionRun_d315 {
  strings:
    $key_d315 = { 80 7a [2] a4 74 [2] 8f 58 [2] a1 7a [2] b5 61 [2] ba 7b [2] a4 66 [2] a6 67 [2] bd 61 [2] a1 66 [2] bd 49 }

  condition:
    any of them
}