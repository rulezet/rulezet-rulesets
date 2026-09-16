rule TTP_XOR_QUAD_CurrentVersionRun_d362 {
  strings:
    $key_d362 = { 80 0d [2] a4 03 [2] 8f 2f [2] a1 0d [2] b5 16 [2] ba 0c [2] a4 11 [2] a6 10 [2] bd 16 [2] a1 11 [2] bd 3e }

  condition:
    any of them
}