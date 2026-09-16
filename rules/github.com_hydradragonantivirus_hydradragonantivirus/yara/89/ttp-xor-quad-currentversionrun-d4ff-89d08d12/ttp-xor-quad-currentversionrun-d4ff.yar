rule TTP_XOR_QUAD_CurrentVersionRun_d4ff {
  strings:
    $key_d4ff = { 87 90 [2] a3 9e [2] 88 b2 [2] a6 90 [2] b2 8b [2] bd 91 [2] a3 8c [2] a1 8d [2] ba 8b [2] a6 8c [2] ba a3 }

  condition:
    any of them
}