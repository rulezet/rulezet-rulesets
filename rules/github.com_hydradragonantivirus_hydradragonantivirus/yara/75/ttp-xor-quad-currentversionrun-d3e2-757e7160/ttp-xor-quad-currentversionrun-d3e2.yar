rule TTP_XOR_QUAD_CurrentVersionRun_d3e2 {
  strings:
    $key_d3e2 = { 80 8d [2] a4 83 [2] 8f af [2] a1 8d [2] b5 96 [2] ba 8c [2] a4 91 [2] a6 90 [2] bd 96 [2] a1 91 [2] bd be }

  condition:
    any of them
}