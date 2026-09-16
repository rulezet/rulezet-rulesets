rule TTP_XOR_QUAD_CurrentVersionRun_cae2 {
  strings:
    $key_cae2 = { 99 8d [2] bd 83 [2] 96 af [2] b8 8d [2] ac 96 [2] a3 8c [2] bd 91 [2] bf 90 [2] a4 96 [2] b8 91 [2] a4 be }

  condition:
    any of them
}