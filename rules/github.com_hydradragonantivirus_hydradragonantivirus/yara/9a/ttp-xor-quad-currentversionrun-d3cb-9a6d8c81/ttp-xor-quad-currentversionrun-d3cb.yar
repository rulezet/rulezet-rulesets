rule TTP_XOR_QUAD_CurrentVersionRun_d3cb {
  strings:
    $key_d3cb = { 80 a4 [2] a4 aa [2] 8f 86 [2] a1 a4 [2] b5 bf [2] ba a5 [2] a4 b8 [2] a6 b9 [2] bd bf [2] a1 b8 [2] bd 97 }

  condition:
    any of them
}