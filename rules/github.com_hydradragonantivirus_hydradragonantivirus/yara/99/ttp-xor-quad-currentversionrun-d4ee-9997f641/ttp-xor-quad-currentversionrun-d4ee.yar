rule TTP_XOR_QUAD_CurrentVersionRun_d4ee {
  strings:
    $key_d4ee = { 87 81 [2] a3 8f [2] 88 a3 [2] a6 81 [2] b2 9a [2] bd 80 [2] a3 9d [2] a1 9c [2] ba 9a [2] a6 9d [2] ba b2 }

  condition:
    any of them
}