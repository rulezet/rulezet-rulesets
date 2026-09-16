rule TTP_XOR_QUAD_CurrentVersionRun_d3e3 {
  strings:
    $key_d3e3 = { 80 8c [2] a4 82 [2] 8f ae [2] a1 8c [2] b5 97 [2] ba 8d [2] a4 90 [2] a6 91 [2] bd 97 [2] a1 90 [2] bd bf }

  condition:
    any of them
}