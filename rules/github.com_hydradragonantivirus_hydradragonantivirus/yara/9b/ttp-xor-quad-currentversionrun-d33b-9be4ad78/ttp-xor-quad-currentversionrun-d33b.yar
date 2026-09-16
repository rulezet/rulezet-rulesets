rule TTP_XOR_QUAD_CurrentVersionRun_d33b {
  strings:
    $key_d33b = { 80 54 [2] a4 5a [2] 8f 76 [2] a1 54 [2] b5 4f [2] ba 55 [2] a4 48 [2] a6 49 [2] bd 4f [2] a1 48 [2] bd 67 }

  condition:
    any of them
}